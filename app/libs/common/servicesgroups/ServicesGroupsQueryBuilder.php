<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/7/16 - 12:23
 */
/*namespace PaloAltoNetworks\Address;

class AddressGroupsQueryBuilder{

    private $conditions='';
    private $start='1';
    private $limit='25';
    private $membersExploded=false;
    private $compareValue='=0';

    public function __constructor(){

    }

    public function setParams(ARRAY $params){
        if(isset($params['conditions'])) {
            $this->conditions = $params['conditions'];
        }
        if(isset($params['membersExploded'])) {
            $this->membersExploded = $params['membersExploded'];
        }
        if(isset($params['compareValue'])) {
            $this->compareValue = $params['compareValue'];
        }
        if (isset($params['start'])) {
            $this->start = $params['start'];
        }
        if (isset($params['limit'])) {
            $this->limit = $params['limit'];
        }
    }

    public function getQueryLimit(){
        $having = array();
        if (preg_match("/WHERE/", $this->conditions)) {
            $query = "SELECT a.*, count(b.id) as total FROM address_groups_id a
                            LEFT JOIN address_groups b ON a.id = b.lid
                                  $this->conditions
                            GROUP BY a.id
                            HAVING ";
            foreach ($this->compareValue as $compare){
                    $having[] = " total $compare ";
            }
            $query .= implode(' OR ', $having);
            $query .= " ORDER BY a.name ASC LIMIT $this->start, $this->limit";
        }
        else{
            $query = "SELECT a.*, count(b.id) as total FROM address_groups_id a
                            LEFT JOIN address_groups b ON a.id = b.lid
                            WHERE $this->conditions
                            GROUP BY a.id
                            HAVING ";
            foreach ($this->compareValue as $compare){
                $having[] = " total $compare ";
            }
            $query .= implode(' OR ', $having);
            $query .= " ORDER BY a.name ASC LIMIT $this->start, $this->limit";
        }
        return $query;
    }

    public function getQueryCount(){
        $having = array();
        if (preg_match("/WHERE/", $this->conditions)) {
            $query = "SELECT count(*) as total FROM address_groups_id a
                            LEFT JOIN address_groups b ON a.id = b.lid
                                  $this->conditions
                            GROUP BY a.id
                            HAVING ";
            foreach ($this->compareValue as $compare){
                $having[] = " count(b.id) $compare ";
            }
            $query .= implode(' OR ', $having);
        }
        else{
            $query = "SELECT count(*) as total FROM address_groups_id a
                            LEFT JOIN address_groups b ON a.id = b.lid
                            WHERE $this->conditions
                            GROUP BY a.id
                            HAVING ";
            foreach ($this->compareValue as $compare){
                $having[] = " count(b.id) $compare ";
            }
            $query .= implode(' OR ', $having);
        }
        return $query;
    }

    public function getQueryAll(){
        $having = array();
        if (preg_match("/WHERE/", $this->conditions)) {
            $query = "SELECT a.*, count(b.id) as total FROM address_groups_id a
                      LEFT JOIN address_groups b ON a.id = b.lid
                             $this->conditions
                      GROUP BY a.id
                      HAVING ";
            foreach ($this->compareValue as $compare){
                $having[] = " count(b.id) $compare ";
            }
            $query .= implode(' OR ', $having);
        }
        else{
            $query = "SELECT a.*, count(b.id) as total FROM address_groups_id a
                      LEFT JOIN address_groups b ON a.id = b.lid
                      WHERE $this->conditions
                      GROUP BY a.id
                      HAVING ";
            foreach ($this->compareValue as $compare){
                $having[] = " count(b.id) $compare ";
            }
            $query .= implode(' OR ', $having);
        }
        return $query;
    }
}
 * 
 */