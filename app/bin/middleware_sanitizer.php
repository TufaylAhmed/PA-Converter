<?php

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/database.php';

if(isset($post_vars)){
    $excluded = [];
    if(isset($excludeAttributes)) {
        foreach ($post_vars as $key => $value) {
            // Check if the key matches your desired condition
            if (in_array($key, $excludeAttributes)) {
                // Copy the value into the $matchedValues array
                $excluded[$key] = $value;
                unset($post_vars[$key]);
            }
        }
    }
    $post_vars = array_map("escapeStringMiddleWareSanitizer", $post_vars);
    $post_vars = array_map("escapeHtmlSpecialChars", $post_vars);
    if (count($excluded) > 0) {
        $post_vars = array_merge($post_vars, $excluded);
    }
}
if(isset($data)){
    $excluded = [];
    if(isset($excludeAttributes)) {
        foreach ($data as $key => $value) {
            // Check if the key matches your desired condition
            if (in_array($key, $excludeAttributes)) {
                // Copy the value into the $matchedValues array
                $excluded[$key] = $value;
                unset($data[$key]);
            }
        }
    }
    $data = array_map("escapeStringMiddleWareSanitizer", $data);
    $data = array_map("escapeHtmlSpecialChars", $data);
    if (count($excluded) > 0) {
        $data = array_merge($data, $excluded);
    }
}
if(isset($_GET)){
    $excluded = [];
    if(isset($excludeAttributes)) {
        foreach ($_GET as $key => $value) {
            // Check if the key matches your desired condition
            if (in_array($key, $excludeAttributes)) {
                // Copy the value into the $matchedValues array
                $excluded[$key] = $value;
                unset($_GET[$key]);
            }
        }
    }
    $_GET = array_map("escapeStringMiddleWareSanitizer", $_GET);
    $_GET = array_map("escapeHtmlSpecialChars", $_GET);
    if (count($excluded) > 0) {
        $_GET = array_merge($_GET, $excluded);
    }
}
if(isset($_POST)){
    $excludeAttributes = ['xml','protocol']; // Array of attributes to exclude
    $excluded = [];
    if(isset($excludeAttributes)) {
        foreach ($_POST as $key => $value) {
            // Check if the key matches your desired condition
            if (in_array($key, $excludeAttributes)) {
                // Copy the value into the $matchedValues array
                $excluded[$key] = $value;
                unset($_POST[$key]);
            }
        }
    }
    $_POST = array_map("escapeStringMiddleWareSanitizer", $_POST);
    $_POST = array_map("escapeHtmlSpecialChars", $_POST);
    if (count($excluded) > 0) {
        $_POST = array_merge($_POST, $excluded);
    }
}
