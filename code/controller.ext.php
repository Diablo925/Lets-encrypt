<?php


/**
	* Controller for Let_Encrypt module for sentora version 1.0.3
	* Version : 100
	* Author  : Diablo925
*/
class Logger
{
	function __call($name, $arguments)
	{
		echo date('Y-m-d H:i:s')." [$name] ${arguments[0]}\n";
	}
}

$logger = new Logger();

class module_controller extends ctrl_module
{

	static function getList_of_domains()
	{
		$currentuser = ctrl_users::GetUserDetail();
		return self::Show_list_of_domains($currentuser['userid']);
	}

	static function Show_list_of_domains()
	{
		global $zdbh, $controller;

        $currentuser = ctrl_users::GetUserDetail();
		$sql = "SELECT * FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
        $numrows = $zdbh->prepare($sql);
        $numrows->bindParam(':userid', $currentuser['userid']);
        $numrows->execute();
        if ($numrows->fetchColumn() <> 0) {
            $sql = $zdbh->prepare($sql);
            $sql->bindParam(':userid', $currentuser['userid']);
            $res = array();
            $sql->execute();
            while ($rowdomains = $sql->fetch()) {
			//check if folder ssl exists
				if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl") ) {
					mkdir (ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl");
				}
			//check if cert exist or not
				if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rowdomains['vh_name_vc'] ."/") ) {

					$button = '<form action="./?module=Let_Encrypt&action=MakeSSL" method="post">
					<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
					<button class="button-loader btn btn-primary" type="submit" id="button" name="in" id="inMakeSSL" value="inMakeSSL">Encrypt</button>
					</form>';
					$days = "";
				} else {
					$button = '<form action="./?module=Let_Encrypt&action=Delete" method="post">
					<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
					<button class="button-loader btn btn-warning" type="submit" id="button" name="inDeleteSSL" id="inDeleteSSL" value="inDeleteSSL">Delete</button>
					</form>';
					$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rowdomains['vh_name_vc'] ."/cert.pem"));
					$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
					$now = time();
					$your_date = strtotime("$validTo");
					$datediff = $your_date - $now;
					$day = floor($datediff / (60 * 60 * 24));
					if($day <= "-1700") {
					$days = "Not initialized yet"; } else {
					$days = "Expiry in ". $day . " days";
					}
				}
					$res[] = array('Domain' => $rowdomains['vh_name_vc'], 'Button' => $button, 'Days' =>  $days);
			}
			return $res;
		}
			else
				{
				return false;
				}
		}

		static function doMakeSSL()
		{
			global $controller;
			$currentuser = ctrl_users::GetUserDetail();
        	$formvars = $controller->GetAllControllerRequests('FORM');
        	if (self::ExecuteMakeSSL($formvars['inDomain'], $currentuser["username"]))
            return true;
		}
		static function ExecuteMakeSSL($domain, $username)

		{
			global $zdbh, $controller;
			$zsudo = ctrl_options::GetOption('zsudo');
			$currentuser = ctrl_users::GetUserDetail();
			$username = $currentuser["username"];
			$userid = $currentuser["userid"];
			$certlocation = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/";
			$domain_folder = str_replace(".","_", $domain);
			$Domainroot = "/var/sentora/hostdata/".$username."/public_html/".$domain_folder;

			require("modules/Let_Encrypt/code/Lescript.php");
			date_default_timezone_set("UTC");
			//Make Let´s encrypt SSL
			try
			{

				$le = new Analogic\ACME\Lescript($certlocation, $Domainroot, $logger);
				$le->initAccount();
				$le->signDomains(array($domain));
			}
			catch (\Exception $e)
			{
				$logger->error($e->getMessage());
				$logger->error($e->getTraceAsString());
				exit(1);
			}

				$line = "# Lets Encrypt start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . $certlocation . $domain. "/cert.pem". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . $certlocation . $domain. "/private.pem". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . $certlocation . $domain."/chain.pem". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Lets Encrypt end" . fs_filehandler::NewLine();

				$port 			= 443;
				$portforward 	= 1;

				$sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
            	$sql->bindParam(':domain', $domain);
            	$sql->execute();
            	while ($row = $sql->fetch())
				{
					$olddata = $row['vh_custom_tx'];
				}
					$data = $olddata.$line;
					$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx=:data, vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
        	$sql->bindParam(':data', $data);
					$sql->bindParam(':domain', $domain);
					$sql->bindParam(':port', $port);
					$sql->bindParam(':portforward', $portforward);
					$sql->execute();

					//Examine if cron script exists
					if (fs_director::CheckForEmptyValue(self::CheckCronForErrors())) {
					// if it not found it will make it
					$script = "Cron.php";
					$desc = "Made by Let´s Encrypt";
					$timing = "0 0 * * *";
					$full_path = "/usr/bin/php5 -q /etc/sentora/panel/modules/".$controller->GetCurrentModule() ."/code/Corn.php u=". $username ." 2>&1";

					$sql = $zdbh->prepare("INSERT INTO x_cronjobs (ct_acc_fk, ct_script_vc, ct_timing_vc, ct_fullpath_vc, ct_description_tx, ct_created_ts) VALUES (:userid, :script, :timing, :fullpath, :description, ".time().")");
					$sql->execute(array(
					"userid" => $userid,
					"script" => $script,
				 	"timing" => $timing,
					"fullpath" => $full_path,
					"description" => $desc));
					self::WriteCronFile();
				}
					self::SetWriteApacheConfigTrue();
					return true;
		}

		static function doDelete()
	  {
	        global $controller;
	        $currentuser = ctrl_users::GetUserDetail();
	        $formvars = $controller->GetAllControllerRequests('FORM');
	        if (self::ExecuteDelete($formvars['inDomain'], $currentuser["username"]))
	        return true;
	  }

					static function ExecuteDelete($domain, $username)
				 {
					 global $zdbh;
					 global $controller;
					 $currentuser = ctrl_users::GetUserDetail();
					 $rootdir = str_replace('.', '_', $domain);
					 $dir = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/". $domain;
					 $objects = scandir($dir);
			     foreach ($objects as $object) {
			       if ($object != "." && $object != "..") {
			         unlink($dir."/".$object);
			       }
			     }
				 rmdir($dir);

								$port 			= NULL;
								$portforward	= NULL;
								$new = '';

							$line = "# Lets Encrypt start" . fs_filehandler::NewLine();
							$line .= fs_filehandler::NewLine();
			        $line .= 'SSLEngine On' . fs_filehandler::NewLine();
							$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $domain. "/cert.pem". fs_filehandler::NewLine();
							$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $domain. "/private.pem". fs_filehandler::NewLine();
							$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $domain."/chain.pem". fs_filehandler::NewLine();
							$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
							$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
							$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
							$line .= "# Lets Encrypt end" . fs_filehandler::NewLine();


						$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx = replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");

			        	$sql->bindParam(':data', $line);
						$sql->bindParam(':new', $new);
						$sql->bindParam(':domain', $domain);
						$sql->bindParam(':port', $port);
						$sql->bindParam(':portforward', $portforward);
			        	$sql->execute();
						self::SetWriteApacheConfigTrue();
						return true;
				 }

		static function CheckCronForErrors()
    {
        global $zdbh, $controller;
				$currentuser = ctrl_users::GetUserDetail();
				$username = $currentuser["username"];
				$userid = $currentuser["userid"];
				$full_path = "/usr/bin/php5 -q /etc/sentora/panel/modules/".$controller->GetCurrentModule() ."/code/Corn.php u=". $username ." 2>&1";
        $retval = FALSE;


		$sql = "SELECT COUNT(*) FROM x_cronjobs WHERE ct_acc_fk=:userid AND ct_fullpath_vc=:infull AND ct_deleted_ts IS NULL";
		$numrows = $zdbh->prepare($sql);
		$numrows->bindParam(':userid', $userid);
		$numrows->bindParam(':infull', $full_path);
		if ($numrows->execute()) {
				if ($numrows->fetchColumn() <> 0) {
						$retval = TRUE;
				}
		}
		return $retval;
}

static function WriteCronFile()
{
		global $zdbh;
		$currentuser = ctrl_users::GetUserDetail();
		$line = "";
		$sql = "SELECT * FROM x_cronjobs WHERE ct_deleted_ts IS NULL";
		$numrows = $zdbh->query($sql);

		//common header whatever there are some cron task or not
				$line .= 'SHELL=/bin/bash' . fs_filehandler::NewLine();
				$line .= 'PATH=/sbin:/bin:/usr/sbin:/usr/bin' . fs_filehandler::NewLine();
				$line .= 'HOME=/' . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();

		$line .= "#################################################################################" . fs_filehandler::NewLine();
		$line .= "# CRONTAB FOR SENTORA CRON MANAGER MODULE                                        " . fs_filehandler::NewLine();
		$line .= "# Module Developed by Bobby Allen, 17/12/2009                                    " . fs_filehandler::NewLine();
		$line .= "# File automatically generated by Sentora " . sys_versions::ShowSentoraVersion() . fs_filehandler::NewLine();
		$line .= "#################################################################################" . fs_filehandler::NewLine();
		$line .= "# NEVER MANUALLY REMOVE OR EDIT ANY OF THE CRON ENTRIES FROM THIS FILE,          " . fs_filehandler::NewLine();
		$line .= "#  -> USE SENTORA INSTEAD! (Menu -> Advanced -> Cron Manager)                    " . fs_filehandler::NewLine();
		$line .= "#################################################################################" . fs_filehandler::NewLine();

		//Write command lines in crontab, if any
		if ($numrows->fetchColumn() <> 0) {
				$sql = $zdbh->prepare($sql);
				$sql->execute();
				while ($rowcron = $sql->fetch()) {
						$fetchRows = $zdbh->prepare("SELECT * FROM x_accounts WHERE ac_id_pk=:userid AND ac_deleted_ts IS NULL");
						$fetchRows->bindParam(':userid', $rowcron['ct_acc_fk']);
						$fetchRows->execute();
						$rowclient = $fetchRows->fetch();
						if ($rowclient && $rowclient['ac_enabled_in'] <> 0) {
								$line .= "# CRON ID: " . $rowcron['ct_id_pk'] . fs_filehandler::NewLine();
								$line .= $rowcron['ct_timing_vc'] . " " . $rowcron['ct_fullpath_vc'] . fs_filehandler::NewLine();
								$line .= "# END CRON ID: " . $rowcron['ct_id_pk'] . fs_filehandler::NewLine();
						}
				}
		}
		if (fs_filehandler::UpdateFile(ctrl_options::GetSystemOption('cron_file'), 0644, $line)) {
						$returnValue = ctrl_system::systemCommand(
															 ctrl_options::GetSystemOption('zsudo'), array(
																	ctrl_options::GetSystemOption('cron_reload_command'),
																	ctrl_options::GetSystemOption('cron_reload_flag'),
																	ctrl_options::GetSystemOption('cron_reload_user'),
																	ctrl_options::GetSystemOption('cron_reload_path'),
															 )
													 );
				return true;
		} else {
				return false;
		}
}

	static function SetWriteApacheConfigTrue()
    	{
        	global $zdbh;
        	$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx='true'	WHERE so_name_vc='apache_changed'");
        	$sql->execute();
    	}

	static function getResult()
    	{
        	return;
    	}

}
?>
