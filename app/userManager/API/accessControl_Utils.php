<?php
function getOrCreateApiKey(string $api_key, string $valid_til, int $user_id){

    $givenDate = strtotime($valid_til);
    $currentDate = time();

    if(isset($api_key)
        && isset($givenDate)
        && $api_key!=""
        && $givenDate > $currentDate){
        return $api_key;
    }else{
        $api_key = base64_encode(random_bytes(64));

        $conn = get_pdo("pandbRBAC");
        $stmt = $conn->prepare("UPDATE users SET api_key= ?, valid_til = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE id= ? ;");
        $stmt->bindParam(1, $api_key);
        $stmt->bindParam(2, $user_id);
        $stmt->execute();
    }
    return $api_key;
}