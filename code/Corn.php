<?php
if(PHP_SAPI != 'cli') {
echo "only from command line";
exit;
}
			set_time_limit(0);
			date_default_timezone_set("UTC");
			$rawPath = str_replace("\\", "/", dirname(__FILE__));
			$rootPath = str_replace("/modules/Let_Encrypt/code", "/", $rawPath);
			chdir($rootPath);

			require_once 'dryden/loader.inc.php';
			require_once 'cnf/db.php';
			require_once 'inc/dbc.inc.php';
			require 'autorenew.php';

			parse_str(implode('&', array_slice($argv, 1)), $_GET);
			$u = $_GET["u"];
				$dir = ctrl_options::GetSystemOption('hosted_dir') . $u. "/ssl/";

				$folders = array('.', '..', '_account');
					$files = array_diff(scandir($dir), $folders);
					$implodedomain = implode(', ', $files);
							foreach ($files as $value) {
								$rootdir = str_replace('.', '_', $value);
								//$items = ctrl_options::GetSystemOption('hosted_dir') . $u . "/Public_html/".$rootdir."";
								//begin to see if cert need to get updatet
								if (time() > Certvalid("$dir"."$value"."/cert.pem")) {
									$le = new Analogic\ACME\Lescript($dir,ctrl_options::GetSystemOption('hosted_dir') . $u . "/public_html/$rootdir");
									$le->initAccount();
									$le->signDomains(array($value));
									reload();
								}
							}

							function reload()
					    {
								$command = ctrl_options::GetSystemOption('zsudo');
		            $args = array(
		                "service",
		                ctrl_options::GetSystemOption('apache_sn'),
		                ctrl_options::GetSystemOption('apache_restart')
		            );
		            $returnValue = ctrl_system::systemCommand($command, $args);
					    }

								function Certvalid($path)
								{
									$certinfo = openssl_x509_parse(file_get_contents($path));
									return $certinfo["validTo_time_t"] - (86400*30);
								}
?>
