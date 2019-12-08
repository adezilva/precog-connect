<?php
// Purpose: To pull saved logs
function pkcs7_unpad($data, $blocksize)
{
	$pad   = ord($data[($len = strlen($data)) - 1]);
	return substr($data, 0, strlen($data) - $pad);
}
function decrypt($data, $key, $iv) {
	$blocksize = mcrypt_get_block_size('rijndael_128', 'cbc');
	$decoded = base64_decode($data);
	$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $decoded, MCRYPT_MODE_CBC, $iv);
	return pkcs7_unpad($decrypted, $blocksize);
}
function infoarmor_query($method, $criteria) {
	$infoarmorsvr = "https://<gotta get new one>";
	$infoapikey = "";
	$infoapisecret = "";
	$domain_infoapikey = "";
	$domain_infoapisecret = "";
	// API methods:
	// /risk/cards/get
	// /ecrime/posts/query
	// /es/fulltext/query
	// /leaks/info
	// /leaks/get
	// /accounts/targets
	// /domains/info (GET)
    // /reports/info (GET)
	// /reports/get
	// /watchlist
	// /usage/info
	// /fulltext/query
	switch ($method) {
		case "HostLookup";
			$methodkey = $infoapikey.time()."vi.hosts.get".$infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/2/vi/hosts/get?key=".$infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $infoapisecret)."&q_address=".$criteria;
			$returnvar = process_json(file_get_contents($query));
			break;
		case "Infected";
			$methodkey = $infoapikey.time()."si.infected.query".$infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/2/si/infected/query?key=".$infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $infoapisecret)."&q_address=".$criteria;
			break;
		case "CompCredCheck";
			$methodkey = $domain_infoapikey.time()."accounts.check".$domain_infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/2/accounts/check?key=".$domain_infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $domain_infoapisecret)."&account_identifier=".$criteria;
			break;
		case "CompCredQuery";
			$methodkey = $domain_infoapikey.time()."domains.query".$domain_infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/1/domains/query?key=".$domain_infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $domain_infoapisecret)."&DaysAgo=5&domain_identifier=".$criteria;
			break;
		case "eCrime";
			$methodkey = $infoapikey.time()."ecrime.posts.query".$infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/1/ecrime/posts/query?key=".$infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $infoapisecret)."&query".$criteria."&start=".date("dmY");
			$jsontext = json_decode(file_get_contents($query), true);
			//foreach($jsontext['accounts'] as $retval) {
			//	echo "UserID: ".$retval['plain'].", Leak_Id: ".$retval['leak_id']."\n";
			//}
			echo file_get_contents($query);
			echo $query;
			break;
		case "DomainInfo";
			$methodkey = $domain_infoapikey.time()."domains.info".$domain_infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/1/domains/info?key=".$domain_infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $domain_infoapisecret)."&days_ago=7&domain_identifier=".$criteria."&subdomains=1";
			$jsontext = json_decode(file_get_contents($query), true);
			echo "Domain: ".$jsontext['domain']."\n";
			echo "First Seen: ".$jsontext['first_seen']."\n";
			echo "Last Seen: ".$jsontext['last_seen']."\n";
			//foreach($jsontext['accounts'] as $retval) {
			//	echo "UserID: ".$retval['plain'].", Leak_Id: ".$retval['leak_id']."\n";
			//}
			break;
		case "DomainSnippet";
			$methodkey = $domain_infoapikey.time()."domains.snippet".$domain_infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/1/domains/snippet?key=".$domain_infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $domain_infoapisecret)."&days_ago=7&domain_identifier=".$criteria."&subdomains=1";
			$jsontext = json_decode(file_get_contents($query), true);
			echo "Number of accounts found: ".$jsontext['count'].", on Domain: ".$jsontext['domain_identifier']."\n\n";
			foreach($jsontext['accounts'] as $retval) {
				echo "UserID: ".$retval['plain'].", Leak_Id: ".$retval['leak_id']."\n";
			}
			break;
		case "DomainQuery";
			$methodkey = $domain_infoapikey.time()."domains.query".$domain_infoapisecret;
			$query = "https://vigilanteati.infoarmor.com/api/1/domains/query?key=".$domain_infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $domain_infoapisecret)."&days_ago=7&domain_identifier=".$criteria;
			$client = new GuzzleHttp\Client();
			$res = $client->request('GET', $query);
			echo $res->getStatusCode();
			// "200"
			echo $res->getHeader('content-type');
			// 'application/json; charset=utf8'
			echo $res->getBody();
			//$jsontext = json_decode(file_get_contents($query), true);
			echo "Number of accounts found: ".$jsontext['count'].", on Domain: ".$jsontext['domain_identifier']."\n\n";
			foreach($jsontext['accounts'] as $retval) {
				echo "UserID: ".$retval['plain'].", Leak_Id: ".$retval['leak_id'].", Password: ".$retval['password'].", cracked: ".$retval['cracked']."\n";
				//echo decrypt($retval['password'], 'eihkgliahg;ieuhr', '4r72=N>#/927643r');
				//echo decrypt($retval['cracked'], 'eihkgliahg;ieuhr', '4r72=N>#/927643r');
			}
			//echo file_get_contents($query);
			break;
		case "FullText";
				$methodkey = $infoapikey.time()."fulltext/query".$infoapisecret;
				$query = "https://vigilanteati.infoarmor.com/api/1/fulltext/query?key=".$domain_infoapikey."&ts=".time()."&hmac=".hash_hmac('sha1', $methodkey, $domain_infoapisecret)."&query=".$criteria;
				echo $query."\n\n\n";
				$jsontext = json_decode(file_get_contents($query, true));
				echo "Number of accounts found: ".$jsontext['count'].", on $criteria: ".$criteria."\n\n";
				echo $jsontext;
			break;
	}
    //return $query;
}
function process_json($jtext) {
	$jsontext = json_decode($jtext, true);
	echo "Number of accounts found: ".$jsontext['count'].", on Domain: ".$jsontext['domain_identifier']."\n\n";
    echo "<table><body><tr><th>Email Address</th><th>Leak_ID</th></tr>\n";
    //echo array_keys($jsontext['accounts'])."\n\n";
	foreach($jsontext['accounts'] as $retval) {
		//echo $retval.' - '.$retval2.'<br>';
		echo "<tr><td>".$retval['plain']."</td><td>".$retval['leak_id']."</td></tr>\n";
	}
	echo "</body></table>";
}
?>
