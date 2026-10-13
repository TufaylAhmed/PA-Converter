<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
require_once "FilesystemRegexFilter.php";

class FilenameFilter extends FilesystemRegexFilter {
    // Filter files against the regex
    public function accept() {
        return ( ! $this->isFile() || preg_match($this->regex, $this->getFilename()));
    }
}

