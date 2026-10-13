<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
require_once "FilesystemRegexFilter.php";

class DirnameFilter extends FilesystemRegexFilter {
    // Filter directories against the regex
    public function accept() {
        return ( ! $this->isDir() || preg_match($this->regex, $this->getFilename()));
    }
}