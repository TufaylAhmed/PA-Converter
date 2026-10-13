<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2017-Nov-30 08:43
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Security;

class OpenSSLTools{
    private $method;
    private $key;
    private $iv;
    private $option;

    public function __construct(STRING $key, STRING $iv, STRING $method="aes-256-cbc"){
        $this->method = $method;
        $this->key = $key;
        $this->iv = $iv;
        $this->option = OPENSSL_RAW_DATA;
    }

    /***
     * Creates the file and if the parent folders do not exist, creates those
     * @param STRING $filename     Path to the file to create
     * @param STRING $data         Content to put on the file
     * @param int $per      Permissions on the created file
     * @param int $flags
     */
    private function file_force_contents(STRING $filename, STRING $data, INT $per = 0755, INT $flags = 0) {
        $fn = "";
        if(substr($filename, 0, 1) === "/") $fn .= "/";
        $parts = explode("/", $filename);
        $file = array_pop($parts);

        foreach($parts as $part) {
            if(!is_dir($fn .= "$part")) mkdir($fn, $per, true);
            $fn .= "/";
        }
        file_put_contents($fn.$file, $data, $flags);
    }


    /***
     * Encrypts a file into another file
     * @param STRING $in Path for the input file
     * @param STRING $out Path for the output file
     * @return array
     */
    public function encryptFiletoFile(STRING $in, STRING $out){
        $input = file_get_contents($in);
        return $this->encryptToFile($input, $out);
    }

    public function decryptFileFromFile(STRING $in, STRING $out){
        $content = $this->decryptFromFile($in);
        return file_put_contents($out, $content);
    }

    /***
     * Encrypts the $contents to a file $path given the parameters of the OpenSSLTools object
     * @param STRING $content
     * @param STRING $path
     * @return array
     */
    public function encryptToFile(STRING $content, STRING $path):array{
        $encryptedContent = '';
        //echo "Encrypting contens to $path \n";
        $verified = $this->encryptThis($content, $encryptedContent);
        if($verified){
            $this->file_force_contents($path, $encryptedContent);
            return [
                'code'  => true,
                'msg'   => "file encrypted"
            ];
        }
        else{
            return [
                'code'  => false,
                'msg'   => "Problems encrypting file. File could not get verified"
            ];
        }
    }

    /***
     * Decrypts the $contents from a file $path given the parameters of the OpenSSLTools object
     * @param STRING $path
     * @return string
     */
    public function decryptFromFile(STRING $path){
        if(! $contents = file_get_contents($path)){
            return "";
        }
        return openssl_decrypt($contents, $this->method, $this->key, $this->option, $this->iv);
    }

    /***
     * Decrypts a content
     * @param $encrypted
     * @return string
     */
    public function decryptThis($encrypted){
        return openssl_decrypt($encrypted, $this->method, $this->key, $this->option, $this->iv);
    }

    /***
     * Verifies a source has been correctly encrypted, so it will be properly decrypted when needed
     * @param STRING $source
     * @param STRING $encrypted
     * @return bool
     */
    public function verifyEncrypt(STRING $source, STRING $encrypted):bool{
        return ($source == $this->decryptThis($encrypted)) ? true: false;
    }

    /***
     * Given a content returns, via a reference variable $encryptedContent, the content encrypted
     * @param STRING $content           content to encrypt
     * @param INT $maxAttempts          max amount of attempts for the encryption
     * @param STRING $encryptedContent  contents the encrypted content (reference)
     * @return bool                     true is correct encryption, false otherwise
     */
    public function encryptThis(STRING $content, STRING &$encryptedContent, INT $maxAttempts=3):bool{
        $attempts = 0;

        do {
            $encryptedContent = openssl_encrypt($content, $this->method, $this->key, $this->option, $this->iv);
            $verified = $this->verifyEncrypt($content, $encryptedContent);
            $attempts++;
        } while( !$verified && $attempts <= $maxAttempts);

        return $verified;
    }
}
