<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 14/7/16 - 17:41
 */
function getLimitationsPanos(STRING $project, STRING $parameter){
    global $app;

    $projectObj = $app->project->where('name', $project)->get()->first();
    $panosVersion = $projectObj->panos;

    $panosVersion = explode('.', $panosVersion);
    switch ($parameter){
        case 'maxMembersPerGroup':
            if ($panosVersion[0] < '7' || ($panosVersion[0]==7 && $panosVersion[1]<1)) {
                $value = '500';
            }
            else{
                $value = '5000';
            }

            break;

        default:
            break;
    }

    return $value;
}