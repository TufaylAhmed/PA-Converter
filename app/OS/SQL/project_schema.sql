CREATE TABLE `threats_from_log` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `app` varchar(255) NOT NULL,
    `threatid` varchar(255) NOT NULL,
    `action` varchar(255) NOT NULL,
    `tid` bigint(20) NOT NULL,
    `category_of_threatid` varchar(255) NOT NULL,
    `source` int(11) NOT NULL,
    `count` int(11) NOT NULL,
    `rule_lid` int(11) NOT NULL,
    `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
    `subtype` varchar(255) NOT NULL DEFAULT '',
    `severity_of_threatid` varchar(255) NOT NULL DEFAULT '',
    `date_retrieve` datetime NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `id_UNIQUE` (`id`),
    KEY `index1` (`rule_lid`),
    KEY `index2` (`source`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `TPInternetZones` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `source` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `TPInternetExcludedNetworks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `source` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `updates`;
CREATE TABLE `updates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `datetime` datetime DEFAULT NULL,
  `filename` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `bpat_bpcheck`;
CREATE TABLE `bpat_bpcheck` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `topic_id` int(11) DEFAULT NULL,
  `check_id` int(11) DEFAULT NULL,
  `message` varchar(1024) DEFAULT NULL,
  `name` varchar(1024) DEFAULT NULL,
  `result` varchar(45) DEFAULT NULL,
  `type` varchar(45) DEFAULT NULL,
  `rule_lid` int(11) NOT NULL,
  `remediation` int(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `bpat_topic`;
CREATE TABLE `bpat_topic` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `topic` varchar(255) DEFAULT NULL,
  `subtype` varchar(255) DEFAULT NULL,
  `xpath` varchar(1024) DEFAULT NULL,
  `configuration` text,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(250) DEFAULT NULL,
  `template_name` varchar(255) DEFAULT NULL,
  `template` int(11) DEFAULT NULL,
  `timestamp` DATETIME NULL,
  `rule_lid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `minemeld`;
CREATE TABLE `minemeld` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `url` varchar(1024) NOT NULL,
  `hash` varchar(1024) NOT NULL,
  `ssl_verify_peer` INT(1) NOT NULL,
  `ssl_verify_host` INT(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `minemeld_feeds`;
CREATE TABLE `minemeld_feeds` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `feed` varchar(1024) NOT NULL,
  `node_id` int(11) NOT NULL,
  `statistics` text,
  `inputs` text,
  `nodetype` varchar(1024) NOT NULL DEFAULT 'ip',
  `length` int(11) NOT NULL DEFAULT '0',
  `created` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/* Decryption Rules */
-- DROP TABLE IF EXISTS `decryption_rules`;
CREATE TABLE `decryption_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `name` varchar(63) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `description` varchar(1024) NOT NULL,
  `action` varchar(25) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `type` varchar(255) DEFAULT '',
  `type_content` varchar(255) DEFAULT '',
  `certificate` varchar(255) DEFAULT '',
  `profile` varchar(255) DEFAULT '',
  `log_forwarding` varchar(45) NOT NULL,
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_from`;
CREATE TABLE `decryption_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_to`;
CREATE TABLE `decryption_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_srv`;
CREATE TABLE `decryption_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_src`;
CREATE TABLE `decryption_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_dst`;
CREATE TABLE `decryption_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_usr`;
CREATE TABLE `decryption_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_tag`;
CREATE TABLE `decryption_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `decryption_rules_categories`;
CREATE TABLE `decryption_rules_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/* End Decryption Rules */

/* QoS Rules */
-- DROP TABLE IF EXISTS `qos_rules`;
CREATE TABLE `qos_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `description` varchar(1024) NOT NULL,
  `action` int(11) NOT NULL,
  `schedule` varchar(45) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `dscp_tos` varchar(25) DEFAULT 'any',
  `codepoints` TEXT DEFAULT '',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_from`;
CREATE TABLE `qos_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_to`;
CREATE TABLE `qos_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_app`;
CREATE TABLE `qos_rules_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` varchar(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_srv`;
CREATE TABLE `qos_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_src`;
CREATE TABLE `qos_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_dst`;
CREATE TABLE `qos_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_usr`;
CREATE TABLE `qos_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_tag`;
CREATE TABLE `qos_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `qos_rules_categories`;
CREATE TABLE `qos_rules_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/* End QoS Rules */

/* Start PBF Rules */
-- DROP TABLE IF EXISTS `pbf_rules`;
CREATE TABLE `pbf_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `from_type` varchar(31) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `enforce_symmetric_return` longtext NOT NULL,
  `description` varchar(1024) NOT NULL,
  `action` varchar(255) NOT NULL,
  `schedule` varchar(45) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `monitor_profile` varchar(45) NOT NULL,
  `monitor_disable_if_unreachable` varchar(3) NOT NULL,
  `monitor_ipaddress` varchar(255) NOT NULL,
  `nexthop` varchar(255) NOT NULL,
  `egress_interface` varchar(45) NOT NULL,
  `forward_to_vsys` varchar(255) NOT NULL DEFAULT '',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_from`;
CREATE TABLE `pbf_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `type` varchar(200) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_app`;
CREATE TABLE `pbf_rules_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` varchar(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_srv`;
CREATE TABLE `pbf_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_src`;
CREATE TABLE `pbf_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_dst`;
CREATE TABLE `pbf_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_usr`;
CREATE TABLE `pbf_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_tag`;
CREATE TABLE `pbf_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `pbf_rules_nal`;
CREATE TABLE `pbf_rules_nal` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/* End PBF Rules */


/* TUNNEL INSPECT Rules */
-- DROP TABLE IF EXISTS `tunnel_inspect_rules`;
CREATE TABLE `tunnel_inspect_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `description` varchar(1024) NOT NULL,
  `action` int(11) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `log_forwarding` varchar(45) NOT NULL,
  `enable_log_setting` varchar(3) NOT NULL,
  `log_start_log_setting` varchar(3) NOT NULL,
  `log_end_log_setting` varchar(3) NOT NULL,
  `monitor_name_tunnel` varchar(255) NOT NULL,
  `monitor_id_tunnel` varchar(255) NOT NULL,
  `inspect_options` longtext NOT NULL,
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_from`;
CREATE TABLE `tunnel_inspect_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_to`;
CREATE TABLE `tunnel_inspect_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_app`;
CREATE TABLE `tunnel_inspect_rules_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` varchar(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_src`;
CREATE TABLE `tunnel_inspect_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_dst`;
CREATE TABLE `tunnel_inspect_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_usr`;
CREATE TABLE `tunnel_inspect_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_tag`;
CREATE TABLE `tunnel_inspect_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


/* Authentication Rules */
-- DROP TABLE IF EXISTS `authentication_rules`;
CREATE TABLE `authentication_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `name` varchar(63) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `description` varchar(1024) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `type` varchar(255) DEFAULT '',
  `authentication_enforcement` varchar(255) DEFAULT '',
  `log_authentication_timeout` varchar(255) DEFAULT '',
  `timeout` varchar(255) DEFAULT '60',
  `log_forwarding` varchar(45) NOT NULL,
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_from`;
CREATE TABLE `authentication_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_to`;
CREATE TABLE `authentication_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_srv`;
CREATE TABLE `authentication_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_src`;
CREATE TABLE `authentication_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_dst`;
CREATE TABLE `authentication_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_usr`;
CREATE TABLE `authentication_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_tag`;
CREATE TABLE `authentication_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_categories`;
CREATE TABLE `authentication_rules_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_hip`;
CREATE TABLE `authentication_rules_hip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  `name` varchar(45) NOT NULL,
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/* End Authentication Rules */


/* Start DoS Rules */
-- DROP TABLE IF EXISTS `dos_rules`;
CREATE TABLE `dos_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `from_type` varchar(31) NOT NULL,
  `to_type` varchar(31) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `protection` longtext NOT NULL,
  `description` varchar(1024) NOT NULL,
  `action` varchar(255) NOT NULL,
  `schedule` varchar(45) NOT NULL,
  `log_forwarding` varchar(45) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `monitor_profile` int(11) NOT NULL DEFAULT '0',
  `monitor_disable_if_unreachable` int(1) NOT NULL DEFAULT '0',
  `monitor_ipaddress` varchar(255) NOT NULL DEFAULT '',
  `forward_to_vsys` varchar(255) NOT NULL DEFAULT '',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_from`;
CREATE TABLE `dos_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `type` varchar(200) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_to`;
CREATE TABLE `dos_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `type` varchar(200) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_srv`;
CREATE TABLE `dos_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_src`;
CREATE TABLE `dos_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_dst`;
CREATE TABLE `dos_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_usr`;
CREATE TABLE `dos_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_tag`;
CREATE TABLE `dos_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


/* Captive Portal Rules */
-- DROP TABLE IF EXISTS `captiveportal_rules`;
CREATE TABLE `captiveportal_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `name` varchar(63) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `description` varchar(1024) NOT NULL,
  `action` varchar(25) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `type` varchar(255) DEFAULT '',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_from`;
CREATE TABLE `captiveportal_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_to`;
CREATE TABLE `captiveportal_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_srv`;
CREATE TABLE `captiveportal_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_src`;
CREATE TABLE `captiveportal_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_dst`;
CREATE TABLE `captiveportal_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_tag`;
CREATE TABLE `captiveportal_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_categories`;
CREATE TABLE `captiveportal_rules_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `captiveportal_rules_target`;
CREATE TABLE `captiveportal_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/* End Captive Portal Rules */

-- DROP TABLE IF EXISTS `password_complexity`;
CREATE TABLE `password_complexity` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `bestpractices_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `bestpractices_results` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `topic` varchar(255) NOT NULL,
  `date` datetime NOT NULL,
  `ackowledge` tinyint(1) DEFAULT NULL,
  `code` int(11) DEFAULT '0',
  `message` text NOT NULL,
  `remediated` tinyint(1) NOT NULL DEFAULT '0',
  `userid` int(11) DEFAULT NULL,
  `remediation_output` text NOT NULL,
  `params` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`topic`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;


-- DROP TABLE IF EXISTS `cisco_nat_global`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cisco_nat_global` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `natid` int(11) NOT NULL,
  `zone` varchar(150) NOT NULL,
  `type` varchar(150) NOT NULL,
  `address` varchar(150) NOT NULL,
  `netmask` varchar(150) NOT NULL,
  `source` varchar(45) NOT NULL,
  `vsys` varchar(45) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(150) NOT NULL,
  `cidr` int(11) NOT NULL,
  `hostname` varchar(250) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`natid`,`zone`,`source`,`vsys`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*!40101 SET character_set_client = @saved_cs_client */;
-- MySQL dump 10.14  Distrib 5.5.41-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: project_schema
-- ------------------------------------------------------
-- Server version	5.5.41-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `address`
--
-- DROP TABLE IF EXISTS `connectors_dg_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `connectors_dg_devices` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `device` varchar(255) NOT NULL,
  `serial` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `active` int(1) NOT NULL,
  `connector_id` int(11) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`connector_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

-- DROP TABLE IF EXISTS `address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `address` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `devicegroup` varchar(31) DEFAULT 'default',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `type` varchar(45) DEFAULT 'ip-netmask',
  `ipaddress` varchar(255) DEFAULT '0.0.0.0',
  `cidr` varchar(45) DEFAULT '',
  `description` varchar(1023) NOT NULL,
  `fqdn` varchar(255) NOT NULL,
  `v4` int(11) NOT NULL DEFAULT '1',
  `v6` int(11) NOT NULL DEFAULT '0',
  `vtype` varchar(45) NOT NULL,
  `source` int(11) NOT NULL,
  `tag` text NOT NULL,
  `zone` varchar(255) NOT NULL,
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) NOT NULL DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`name_ext`),
  KEY `index3` (`vsys`),
  KEY `index4` (`ipaddress`),
  KEY `index5` (`source`,`vsys`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `address_groups`
--

-- DROP TABLE IF EXISTS `address_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `address_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `devicegroup` varchar(255) DEFAULT 'default',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `member` varchar(255) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index2` (`member`),
  KEY `index3` (`vsys`),
  KEY `index1` (`lid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `address_groups_id`
--

-- DROP TABLE IF EXISTS `address_groups_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `address_groups_id` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `devicegroup` varchar(255) DEFAULT 'default',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `type` varchar(100) NOT NULL DEFAULT 'static',
  `source` int(11) NOT NULL,
  `description` varchar(1023) NOT NULL,
  `tag` text NOT NULL,
  `filter` text NOT NULL,
  `zone` varchar(45) NOT NULL,
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  `expression` VARCHAR(8000) NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`name_ext`),
  KEY `index3` (`vsys`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `admin_role`
--

-- DROP TABLE IF EXISTS `admin_role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `admin_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `administrators`
--

-- DROP TABLE IF EXISTS `administrators`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `administrators` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(31) NOT NULL,
  `xml` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `algosec_devices`
--

-- DROP TABLE IF EXISTS `algosec_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `algosec_devices` (
  `ID` varchar(250) NOT NULL,
  `Brand` varchar(45) NOT NULL,
  `Name` varchar(250) NOT NULL,
  `IP` varchar(45) NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `ID_UNIQUE` (`ID`),
  KEY `index1` (`Name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `algosec_policy_mapping`
--

-- DROP TABLE IF EXISTS `algosec_policy_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `algosec_policy_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `Line` text NOT NULL,
  `RuleUid` varchar(255) NOT NULL,
  `DeviceID` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`Line`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `algosec_tags`
--

-- DROP TABLE IF EXISTS `algosec_tags`;
CREATE TABLE `algosec_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `algosec_tags_mapping`
--

-- DROP TABLE IF EXISTS `algosec_tags_mapping`;
CREATE TABLE `algosec_tags_mapping` (
  `id` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `Line` text NOT NULL,
  `RuleUid` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `DeviceID` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`),
  KEY `index2` (`rule_lid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `algosec_tags_values`
--

-- DROP TABLE IF EXISTS `algosec_tags_values`;
CREATE TABLE `algosec_tags_values` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tag_id` int(11) NOT NULL,
  `tag_value` varchar(255) NOT NULL,
  `tag_mapping` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appid_adoption_mapping`
--

-- DROP TABLE IF EXISTS `appid_adoption_mapping`;
CREATE TABLE `appid_adoption_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `dport` varchar(255) NOT NULL,
  `protocol` varchar(45) NOT NULL,
  `isgroup` int(1) NOT NULL DEFAULT '0',
  `group_name` varchar(255) NOT NULL,
  `group_lid` int(20) NOT NULL,
  `group_table` varchar(255) NOT NULL,
  `app_via_log` varchar(255) NOT NULL,
  `proto_via_log` varchar(45) NOT NULL,
  `dport_via_log` varchar(255) NOT NULL,
  `app_id` int(11) NOT NULL,
  `app_table` varchar(255) NOT NULL,
  `application_default` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index2` (`source`),
  KEY `index3` (`dport`,`protocol`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appid_rule_relation`
--

-- DROP TABLE IF EXISTS `appid_rule_relation`;
CREATE TABLE `appid_rule_relation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `origin` int(11) NOT NULL,
  `clone` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications`
--

-- DROP TABLE IF EXISTS `applications`;
CREATE TABLE `applications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `devicegroup` varchar(31) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31) NOT NULL,
  `description` varchar(1023) NOT NULL,
  `category` varchar(150) NOT NULL,
  `subcategory` varchar(150) NOT NULL,
  `parent_app` varchar(150) NOT NULL DEFAULT 'None',
  `risk` int(5) NOT NULL DEFAULT '1',
  `technology` varchar(150) NOT NULL,
  `evasive_behavior` varchar(3) NOT NULL DEFAULT 'no',
  `consume_big_bandwidth` varchar(3) NOT NULL DEFAULT 'no',
  `used_by_malware` varchar(3) NOT NULL DEFAULT 'no',
  `able_to_transfer_file` varchar(3) NOT NULL DEFAULT 'no',
  `has_known_vulnerability` varchar(3) NOT NULL DEFAULT 'no',
  `tunnel_other_application` varchar(3) NOT NULL DEFAULT 'no',
  `tunnel_applications` varchar(3) NOT NULL DEFAULT 'no',
  `prone_to_misuse` varchar(3) NOT NULL DEFAULT 'no',
  `pervasive_use` varchar(3) NOT NULL DEFAULT 'no',
  `file_type_ident` varchar(3) NOT NULL DEFAULT 'no',
  `virus_ident` varchar(3) NOT NULL DEFAULT 'no',
  `data_ident` varchar(3) NOT NULL DEFAULT 'no',
  `default_type` varchar(45) NOT NULL DEFAULT 'None',
  `value` varchar(1023) NOT NULL,
  `type` int(5) NOT NULL,
  `code` int(5) NOT NULL,
  `timeout` varchar(6) NOT NULL,
  `tcp_timeout` varchar(6) NOT NULL,
  `udp_timeout` varchar(6) NOT NULL,
  `tcp_half_closed_timeout` varchar(6) NOT NULL,
  `tcp_time_wait_timeout` varchar(6) NOT NULL,
  `spyware_ident` varchar(3) NOT NULL DEFAULT 'no',
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  `checkit` int(1),
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  `used` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`risk`),
  KEY `index3` (`vsys`),
  KEY `index4` (`source`),
  KEY `index5` (`category`),
  KEY `index6` (`subcategory`),
  KEY `index7` (`technology`),
  KEY `index8` (`evasive_behavior`),
  KEY `index9` (`consume_big_bandwidth`),
  KEY `index10` (`prone_to_misuse`),
  KEY `index11` (`able_to_transfer_file`),
  KEY `index12` (`tunnel_other_application`),
  KEY `index13` (`used_by_malware`),
  KEY `index14` (`has_known_vulnerability`),
  KEY `index15` (`technology`),
  KEY `index16` (`pervasive_use`),
  KEY `index17` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications_filters`
--

-- DROP TABLE IF EXISTS `applications_filters`;
CREATE TABLE `applications_filters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` text,
  `risk` VARCHAR(150) NOT NULL,
  `category` VARCHAR(1024) NOT NULL ,
  `subcategory` VARCHAR(1024) NOT NULL,
  `technology` VARCHAR(1024) NOT NULL,
  `evasive_behavior` VARCHAR(3) NOT NULL,
  `consume_big_bandwidth` VARCHAR(3) NOT NULL,
  `prone_to_misuse` VARCHAR(3) NOT NULL,
  `able_to_transfer_file` VARCHAR(3) NOT NULL,
  `tunnel_other_application` VARCHAR(3) NOT NULL,
  `used_by_malware` VARCHAR(3) NOT NULL,
  `has_known_vulnerability` VARCHAR(3) NOT NULL,
  `pervasive_use` VARCHAR(3) NOT NULL,
  `saas_certifications` VARCHAR(1024) NOT NULL,
  `saas_risk` VARCHAR(1024) NOT NULL,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  `dummy` int(1) DEFAULT '0',
  `used` int(1) DEFAULT '0',
  `tagging` varchar(250) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`risk`),
  KEY `index3` (`vsys`),
  KEY `index4` (`source`),
  KEY `index5` (`category`),
  KEY `index6` (`subcategory`),
  KEY `index7` (`technology`),
  KEY `index8` (`evasive_behavior`),
  KEY `index9` (`consume_big_bandwidth`),
  KEY `index10` (`prone_to_misuse`),
  KEY `index11` (`able_to_transfer_file`),
  KEY `index12` (`tunnel_other_application`),
  KEY `index13` (`used_by_malware`),
  KEY `index14` (`has_known_vulnerability`),
  KEY `index15` (`technology`),
  KEY `index16` (`pervasive_use`),
  KEY `index17` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications_from_log`
--

-- DROP TABLE IF EXISTS `applications_from_log`;
CREATE TABLE `applications_from_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `dport` int(6) NOT NULL,
  `bytes` bigint(20) NOT NULL,
  `packets` bigint(20) NOT NULL,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `proto` varchar(15) NOT NULL DEFAULT 'tcp',
  `date_retrieve` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index2` (`source`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications_groups`
--

-- DROP TABLE IF EXISTS `applications_groups`;
CREATE TABLE `applications_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `used` int(1) DEFAULT '0',
  `xml` text,
  `member` VARCHAR(255) NOT NULL, 
  `member_lid` INT(20) NOT NULL,
  `table_name` VARCHAR(255) NOT NULL,
  `lid` INT(11) NOT NULL,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`),
  KEY `index2` (`name`),
  KEY `index3` (`type`),
  KEY `index4` (`vsys`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications_groups_id`
--

-- DROP TABLE IF EXISTS `applications_groups_id`;
CREATE TABLE `applications_groups_id` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `devicegroup` varchar(255) DEFAULT 'default',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `source` int(11) NOT NULL,
  `invalid` int(1) NOT NULL DEFAULT '0',
  `type` varchar(100) NOT NULL DEFAULT 'static',
  `description` varchar(1023) NOT NULL,
  `tag` text NOT NULL,
  `filter` text NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index3` (`vsys`),
  KEY `index4` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications_signatures`
--

-- DROP TABLE IF EXISTS `applications_signatures`;
CREATE TABLE `applications_signatures` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `signature` text NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `applications_ports`
--

-- DROP TABLE IF EXISTS `applications_ports`;
CREATE TABLE `applications_ports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `ports` text NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appoverride_rules`
--

-- DROP TABLE IF EXISTS `appoverride_rules`;
CREATE TABLE `appoverride_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63),
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `description` varchar(255) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `source` int(11) NOT NULL,
  `target` text NOT NULL,
  `protocol` varchar(45) NOT NULL,
  `port` TEXT NOT NULL,
  `app_id` int(11) NOT NULL,
  `app_table` varchar(255) NOT NULL,
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) DEFAULT 'default',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index0` (`id`),
  KEY `index1` (`position`),
  KEY `index2` (`vsys`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appoverride_rules_dst`
--

-- DROP TABLE IF EXISTS `appoverride_rules_dst`;
CREATE TABLE `appoverride_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `appoverride_rules_from`
--

-- DROP TABLE IF EXISTS `appoverride_rules_from`;
CREATE TABLE `appoverride_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appoverride_rules_src`
--

-- DROP TABLE IF EXISTS `appoverride_rules_src`;
CREATE TABLE `appoverride_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appoverride_rules_tag`
--

-- DROP TABLE IF EXISTS `appoverride_rules_tag`;
CREATE TABLE `appoverride_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `appoverride_rules_to`
--

-- DROP TABLE IF EXISTS `appoverride_rules_to`;
CREATE TABLE `appoverride_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `authentication_profile`
--

-- DROP TABLE IF EXISTS `authentication_profile`;
CREATE TABLE `authentication_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `authentication_sequence`
--

-- DROP TABLE IF EXISTS `authentication_sequence`;
CREATE TABLE `authentication_sequence` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `botnet`
--

-- DROP TABLE IF EXISTS `botnet`;
CREATE TABLE `botnet` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `xml` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `captive_portal`
--

-- DROP TABLE IF EXISTS `captive_portal`;
CREATE TABLE `captive_portal` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `xml` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` int(31) NOT NULL,
  `template` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`template`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `category`
--

-- DROP TABLE IF EXISTS `category`;
CREATE TABLE `category` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `category`
--

LOCK TABLES `category` WRITE;
/*!40000 ALTER TABLE `category` DISABLE KEYS */;
INSERT INTO category VALUES ('1', 'general-internet'), ('2', 'business-systems'), ('3', 'collaboration'), ('4', 'networking'), ('5', 'media'), ('6', 'unknown');
/*!40000 ALTER TABLE `category` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `certificate`
--

-- DROP TABLE IF EXISTS `certificate`;
CREATE TABLE `certificate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `certificate_profile`
--

-- DROP TABLE IF EXISTS `certificate_profile`;
CREATE TABLE `certificate_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `characteristic`;
CREATE TABLE `characteristic` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `version` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `characteristic`
--

LOCK TABLES `characteristic` WRITE;
/*!40000 ALTER TABLE `characteristic` DISABLE KEYS */;
INSERT INTO characteristic VALUES
('1', 'Evasive', '7'),
('2', 'Excessive Bandwidth', '7'),
('3', 'Prone to Misuse', '7'),
('4', 'Transfers Files', '7'),
('5', 'Tunnels Others Apps', '7'),
('6', 'Used by Malware', '7'),
('7', 'Vulnerability', '7'),
('8', 'Widely used', '7'),
('9', 'Data Breaches', '8.1'),
('10', 'FEDRAMP', '8.1'),
('11', 'HIPAA', '8.1'),
('12', 'IP Based Restrictions', '8.1'),
('13', 'No Certifications', '8.1'),
('14', 'PCI', '8.1'),
('15', 'Poor Financial Viability', '8.1'),
('16', 'Poor Terms Of Service', '8.1'),
('17', 'SaaS', '8.1'),
('18', 'SOC I', '8.1'),
('19', 'SOC II', '8.1'),
('20', 'SSAE16', '8.1'),
('21', 'TRUSTe', '8.1');
/*!40000 ALTER TABLE `characteristic` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cisco_icmp_groups`
--

-- DROP TABLE IF EXISTS `cisco_icmp_groups`;
CREATE TABLE `cisco_icmp_groups` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `member` varchar(100) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`member`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `cisco_policy_mapping`
--

-- DROP TABLE IF EXISTS `cisco_policy_mapping`;
CREATE TABLE `cisco_policy_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `line` text NOT NULL,
  `name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`line`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `cisco_protocol_groups`
--

-- DROP TABLE IF EXISTS `cisco_protocol_groups`;
CREATE TABLE `cisco_protocol_groups` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `member` varchar(100) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`member`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `config_views`
--

-- DROP TABLE IF EXISTS `config_views`;
CREATE TABLE `config_views` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `view` varchar(45) NOT NULL DEFAULT 'panos',
  `panorama_devicegroup` varchar(45) NOT NULL DEFAULT 'all',
  `panorama_rules` varchar(45) NOT NULL DEFAULT 'all',
  `panos_vsys` varchar(31) NOT NULL DEFAULT 'all',
  `source` int(11) NOT NULL DEFAULT '0',
  `panorama_template` varchar(45) NOT NULL DEFAULT 'all',
  `version` varchar(10) NOT NULL,
  `user` int(11) NOT NULL,
  `devices` TINYTEXT NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `connectors`
--

-- DROP TABLE IF EXISTS `connectors`;
CREATE TABLE `connectors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `vendor` varchar(150) NOT NULL,
  `image` varchar(255) NOT NULL,
  `device` varchar(255) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `panorama` varchar(255) NOT NULL,
  `period` varchar(45) NOT NULL,
  `starttime` varchar(20) NOT NULL DEFAULT '00:00:00',
  `endtime` varchar(20) NOT NULL DEFAULT '23:59:59',
  `startdate` varchar(20) NOT NULL,
  `enddate` varchar(20) NOT NULL,
  `serial` varchar(255) NULL,
  `top` varchar(45) NOT NULL DEFAULT '500',
  `type` VARCHAR(45) NULL DEFAULT 'static',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`vendor`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `crypto_dh_group`
--

-- DROP TABLE IF EXISTS `crypto_dh_group`;
CREATE TABLE `crypto_dh_group` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `version` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `crypto_dh_group`
--

LOCK TABLES `crypto_dh_group` WRITE;
/*!40000 ALTER TABLE `crypto_dh_group` DISABLE KEYS */;
INSERT INTO crypto_dh_group VALUES ('1', 'group1','group1', '6'), ('2', 'group2','group2', '6'), ('3', 'group5','group5', '6'), ('4', 'group14','group14', '6'),
('5', 'group1','group1', '7'), ('6', 'group2','group2', '7'), ('7', 'group5','group5', '7'), ('8', 'group14','group14', '7'),
('9', 'group19','group19', '7'), ('10', 'group20','group20', '7'), ('11', 'group21', 'group21', '10');
/*!40000 ALTER TABLE `crypto_dh_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `crypto_encryption`
--

-- DROP TABLE IF EXISTS `crypto_encryption`;
CREATE TABLE `crypto_encryption` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `version` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `crypto_encryption`
--

LOCK TABLES `crypto_encryption` WRITE;
/*!40000 ALTER TABLE `crypto_encryption` DISABLE KEYS */;
INSERT INTO crypto_encryption VALUES ('1', '3des','3des', '6'), ('2', 'aes128','aes128', '6'),
('3', 'aes192','aes192', '6'), ('4', 'aes256','aes256', '6'), ('5', '3des','3des', '7'), ('6', 'des','des', '7.1'), ('7', 'aes-128-cbc','aes-128-cbc', '7'),
('8', 'aes-192-cbc','aes-192-cbc', '7'), ('9', 'aes-256-cbc','aes-256-cbc', '7'), ('10', 'aes-128-ccm','aes-128-ccm', '7'),
('11', 'aes-128-gcm','aes-128-gcm', '7'), ('12', 'aes-256-gcm','aes-256-gcm', '7');
/*!40000 ALTER TABLE `crypto_encryption` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `crypto_authentication`
--

-- DROP TABLE IF EXISTS `crypto_authentication`;
CREATE TABLE `crypto_authentication` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `description` VARCHAR(100) NOT NULL,
  `version` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `crypto_authentication`
--

LOCK TABLES `crypto_authentication` WRITE;
/*!40000 ALTER TABLE `crypto_authentication` DISABLE KEYS */;
INSERT INTO crypto_authentication VALUES ('1', 'md5','md5', 'md5', '6'), ('2', 'sha1','sha1', 'sha1', '6'), ('3', 'sha256','sha256', 'sha256', '6'),
('4', 'sha384','sha384', 'sha384', '6'),('5', 'sha512','sha512', 'sha512', '6'), ('6', 'md5','md5', 'md5 (below 80-bit strength)', '7'),
('7', 'sha1','sha1', 'sha1 (NIST rating 128-bit strength)', '7'), ('8', 'sha256','sha256', 'sha256 (NIST rating 256-bit strength)', '7'),
('9', 'sha384','sha384', 'sha384 (NIST rating 256-bit strength)', '7'), ('10', 'sha512','sha512', 'sha512 (NIST rating 256-bit strength)', '7');
/*!40000 ALTER TABLE `crypto_authentication` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `csv_columns`
--

-- DROP TABLE IF EXISTS `csv_columns`;
CREATE TABLE `csv_columns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `objtype` varchar(45) NOT NULL,
  `col0` text NOT NULL,
  `col1` text NOT NULL,
  `col2` text NOT NULL,
  `col3` text NOT NULL,
  `col4` text NOT NULL,
  `col5` text NOT NULL,
  `col6` text NOT NULL,
  `col7` text NOT NULL,
  `col8` text NOT NULL,
  `col9` text NOT NULL,
  `col10` text NOT NULL,
  `col11` text NOT NULL,
  `col12` text NOT NULL,
  `col13` text NOT NULL,
  `col14` text NOT NULL,
  `col15` text NOT NULL,
  `col16` text NOT NULL,
  `col17` text NOT NULL,
  `col18` text NOT NULL,
  `col19` text NOT NULL,
  `col20` text NOT NULL,
  `col21` text NOT NULL,
  `col22` text NOT NULL,
  `col23` text NOT NULL,
  `col24` text NOT NULL,
  `col25` text NOT NULL,
  `col26` text NOT NULL,
  `col27` text NOT NULL,
  `col28` text NOT NULL,
  `col29` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `csv_mapping`
--

-- DROP TABLE IF EXISTS `csv_mapping`;
CREATE TABLE `csv_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `columns` varchar(45) NOT NULL,
  `mapping` varchar(150) NOT NULL,
  `objtype` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `default_applications`
--

-- DROP TABLE IF EXISTS `default_applications`;
CREATE TABLE `default_applications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `version` varchar(45) NOT NULL,
  `risk` int(11) NOT NULL,
  `category` varchar(150) NOT NULL,
  `subcategory` varchar(150) NOT NULL,
  `technology` varchar(150) NOT NULL,
  `evasive_behavior` varchar(3) DEFAULT 'no',
  `consume_big_bandwidth` varchar(3) DEFAULT 'no',
  `used_by_malware` varchar(3) DEFAULT 'no',
  `able_to_transfer_file` varchar(3) DEFAULT 'no',
  `has_known_vulnerability` varchar(3) DEFAULT 'no',
  `tunnel_other_application` varchar(3) DEFAULT 'no',
  `prone_to_misuse` varchar(3) DEFAULT 'no',
  `pervasive_use` varchar(3) DEFAULT 'no',
  `default_port` varchar(355) NOT NULL,
  `default_protocol` int(11) NOT NULL,
  `dependency` mediumtext NOT NULL,
  `functions` mediumtext NOT NULL,
  `implicit` mediumtext NOT NULL,
  `container` varchar(250) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  `is_saas` varchar(3) DEFAULT 'no',
  `certifications` varchar(3) DEFAULT 'no',
  `is_fedramp` varchar(3) DEFAULT 'no',
  `is_hipaa` varchar(3) DEFAULT 'no',
  `is_pci` varchar(3) DEFAULT 'no',
  `is_soc1` varchar(3) DEFAULT 'no',
  `is_soc2` varchar(3) DEFAULT 'no',
  `is_ssae16` varchar(3) DEFAULT 'no',
  `is_truste` varchar(3) DEFAULT 'no',
  `is_data_breaches` varchar(3) DEFAULT 'no',
  `is_ip_based_restrictions` varchar(3) DEFAULT 'no',
  `is_poor_financial_viability` varchar(3) DEFAULT 'no',
  `is_poor_terms_of_service` varchar(3) DEFAULT 'no',
  `ori_country` varchar(255) DEFAULT NULL,
  `used` int(1) DEFAULT '0',
  PRIMARY KEY (`id`,`name`),
  UNIQUE KEY `name_UNIQUE` (`name`),
  KEY `index1` (`name`),
  KEY `index2` (`risk`),
  KEY `index3` (`category`),
  KEY `index4` (`subcategory`),
  KEY `index5` (`technology`),
  KEY `index6` (`evasive_behavior`),
  KEY `index7` (`consume_big_bandwidth`),
  KEY `index8` (`prone_to_misuse`),
  KEY `index9` (`able_to_transfer_file`),
  KEY `index10` (`tunnel_other_application`),
  KEY `index11` (`used_by_malware`),
  KEY `index12` (`has_known_vulnerability`),
  KEY `index13` (`technology`),
  KEY `index14` (`pervasive_use`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `default_regions`
--

-- DROP TABLE IF EXISTS `default_regions`;
CREATE TABLE `default_regions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `help` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `default_url_categories`
--

-- DROP TABLE IF EXISTS `default_url_categories`;
CREATE TABLE `default_url_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `name_ext` varchar(255),
  `database` varchar(50) DEFAULT 'pandb',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `device_mapping`
--

-- DROP TABLE IF EXISTS `device_mapping`;
CREATE TABLE `device_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device` varchar(255) NOT NULL,
  `ispanorama` int(1) NOT NULL DEFAULT '0',
  `active` int(1) NOT NULL DEFAULT '1',
  `version` varchar(45) NOT NULL,
  `project` varchar(255) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `filename` varchar(255) NOT NULL,
  `map_devicegroup` varchar(255) NOT NULL,
  `map_vsys` varchar(45) NOT NULL,
  `baseconfig` int(1) NOT NULL DEFAULT '0',
  `vendor` varchar(45) NOT NULL DEFAULT 'Paloalto Networks',
  `urldb` varchar(45) NOT NULL DEFAULT 'paloaltonetworks',
  PRIMARY KEY (`id`),
  KEY `device` (`device`),
  KEY `index1` (`filename`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `device_usage`
--

-- DROP TABLE IF EXISTS `device_usage`;
CREATE TABLE `device_usage` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `datetime` datetime NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(255) NOT NULL,
  `platform_id` int(11) NOT NULL,
  `panos` varchar(45) NOT NULL,
  `address_max` int(11) NOT NULL,
  `address_used` int(11) NOT NULL,
  `address_unused` int(11) NOT NULL,
  `address_shared` int(11) NOT NULL,
  `device_usagecol` varchar(45) NOT NULL,
  `address_groups_used` int(11) NOT NULL,
  `address_groups_max` int(11) NOT NULL,
  `address_groups_unused` int(11) NOT NULL,
  `address_groups_shared` int(11) NOT NULL,
  `services_max` int(11) NOT NULL,
  `services_used` int(11) NOT NULL,
  `services_unused` int(11) NOT NULL,
  `services_shared` int(11) NOT NULL,
  `services_groups_max` int(11) NOT NULL,
  `services_groups_used` int(11) NOT NULL,
  `services_groups_unused` int(11) NOT NULL,
  `services_groups_shared` int(11) NOT NULL,
  `security_rulebase_max` int(11) NOT NULL,
  `security_rulebase_used` int(11) NOT NULL,
  `security_rulebase_disabled` int(11) NOT NULL,
  `nat_rulebase_max` int(11) NOT NULL,
  `nat_rulebase_used` int(11) NOT NULL,
  `nat_rulebase_disabled` int(11) NOT NULL,
  `zones_max` int(11) NOT NULL,
  `zones_used` int(11) NOT NULL,
  `virtual_routers_max` int(11) NOT NULL,
  `virtual_routers_used` int(11) NOT NULL,
  `vsys_max` int(11) NOT NULL,
  `vsys_used` int(11) NOT NULL,
  `security_profiles_used` int(11) NOT NULL,
  `security_profiles_max` int(11) NOT NULL,
  `appoverride_rulebase_max` int(11) NOT NULL,
  `appoverride_rulebase_used` int(11) NOT NULL,
  `appoverride_rulebase_disabled` int(11) NOT NULL,
  `custom_appid_max` int(11) NOT NULL,
  `custom_appid_used` int(11) NOT NULL,
  `ipsec_tunnels_max` int(11) NOT NULL,
  `ipsec_tunnels_used` int(11) NOT NULL,
  `pct_objects` float NOT NULL,
  `pct_rules` float NOT NULL,
  `pct_network` float NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`platform_id`,`panos`),
  KEY `index2` (`source`,`vsys`),
  KEY `index3` (`datetime`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `deviceconfig`
--

-- DROP TABLE IF EXISTS `deviceconfig`;
CREATE TABLE `deviceconfig` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `devicegroup_mapping`
--

-- DROP TABLE IF EXISTS `devicegroup_mapping`;
CREATE TABLE `devicegroup_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_mapping_id` int(11) NOT NULL,
  `serial` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`device_mapping_id`),
  KEY `index2` (`serial`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- Table structure for table `devicegroups`
--

-- DROP TABLE IF EXISTS `devicegroups`;
CREATE TABLE `devicegroups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `devices` text NOT NULL,
  `master_device` text NOT NULL,
  `description` varchar(255) NOT NULL,
  `source` int(11) NOT NULL,
  `device_mapping_id` int(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
   `parent_dg` int(11) NOT NULL,
  `internal_id` int(11) NOT NULL,
  `max_internal_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`source`),
  KEY `index3` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `dhcp`
--

-- DROP TABLE IF EXISTS `dhcp`;
CREATE TABLE `dhcp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `name` varchar(45) NOT NULL,
  `name_ext` varchar(45),
  `dhcp_type` varchar(45) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`vsys`,`source`,`template`),
  KEY `index2` (`template`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `dns_proxy`
--

-- DROP TABLE IF EXISTS `dns_proxy`;
CREATE TABLE `dns_proxy` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`vsys`,`template`,`source`),
  KEY `index2` (`template`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `edit_table`
--

-- DROP TABLE IF EXISTS `edit_table`;
CREATE TABLE `edit_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ids` int(11) NOT NULL,
  `lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name_lid` varchar(45) NOT NULL,
  `type` varchar(100) NOT NULL,
  `name` varchar(100) NOT NULL,
  `image` varchar(100) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `vsys_member` varchar(31) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `source` int(11) NOT NULL,
  `remove` int(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `external_list`
--

-- DROP TABLE IF EXISTS `external_list`;
CREATE TABLE `external_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `xml` text,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`source`),
  KEY `index3` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `fortinet_ippools`
--

-- DROP TABLE IF EXISTS `fortinet_ippools`;
CREATE TABLE `fortinet_ippools` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `start_ip` varchar(45) NOT NULL,
  `end_ip` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`vsys`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `fortinet_vip`
--

-- DROP TABLE IF EXISTS `fortinet_vip`;
CREATE TABLE `fortinet_vip` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `extip` varchar(45) NOT NULL,
  `extintf` varchar(45) NOT NULL,
  `portforward` varchar(45) NOT NULL,
  `mappedip` varchar(45) NOT NULL,
  `extport` varchar(45) NOT NULL,
  `mappedport` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `protocol` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`vsys`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `fortinet_vipgrp`
--

-- DROP TABLE IF EXISTS `fortinet_vipgrp`;
CREATE TABLE `fortinet_vipgrp` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(100) NOT NULL,
  `member` text NOT NULL,
  `interface` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`source`,`vsys`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `group_mapping`
--

-- DROP TABLE IF EXISTS `group_mapping`;
CREATE TABLE `group_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `hash`
--

-- DROP TABLE IF EXISTS `hash`;
CREATE TABLE `hash` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `filter_hash` varchar(45) NOT NULL,
  `hash` varchar(355) NOT NULL,
  `visible` int(2) NOT NULL,
  `table_name` varchar(31) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `hash_rules`
--

-- DROP TABLE IF EXISTS `hash_rules`;
CREATE TABLE `hash_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hash` varchar(355) NOT NULL,
  `filter_hash` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `visible` int(2) NOT NULL,
  `table_name` varchar(31) NOT NULL,
  `rules_lid` longtext NOT NULL,
  `fixed` int(2) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `ike_crypto_profiles`
--

-- DROP TABLE IF EXISTS `ike_crypto_profiles`;
CREATE TABLE `ike_crypto_profiles` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `encryption` MEDIUMTEXT NOT NULL,
  `hash` MEDIUMTEXT NOT NULL,
  `dh_group` MEDIUMTEXT NOT NULL,
  `seconds` INT(11) NOT NULL,
  `minutes` INT(11) NOT NULL,
  `hours` INT(11) NOT NULL,
  `days` INT(11) NOT NULL,
  `authentication_multiple` INT(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `global_protect_portal`
--

-- DROP TABLE IF EXISTS `global_protect_portal`;
CREATE TABLE `global_protect_portal` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `global_protect_gateway`
--

-- DROP TABLE IF EXISTS `global_protect_gateway`;
CREATE TABLE `global_protect_gateway` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `global_protect_mdm`
--

-- DROP TABLE IF EXISTS `global_protect_mdm`;
CREATE TABLE `global_protect_mdm` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `global_protect_app_ipsec_crypto_profiles`
--

-- DROP TABLE IF EXISTS `global_protect_app_ipsec_crypto_profiles`;
CREATE TABLE `global_protect_app_ipsec_crypto_profiles` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `encryption` MEDIUMTEXT NOT NULL,
  `hash` MEDIUMTEXT NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `ike_gateways_profiles`
--

-- DROP TABLE IF EXISTS `ike_gateways_profiles`;
CREATE TABLE `ike_gateways_profiles` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `version` VARCHAR(100) NOT NULL,
  `dpd_ikev1` VARCHAR(10) NOT NULL,
  `ike_interval_ikev1` INT(3) NOT NULL,
  `retry_ikev1` INT(3) NOT NULL,
  `ike_crypto_profile_ikev1` VARCHAR(150) NOT NULL,
  `exchange_mode_ikev1` VARCHAR(255) NOT NULL,
  `dpd_ikev2` VARCHAR(10) NOT NULL,
  `ike_interval_ikev2` INT(3) NOT NULL,
  `ike_crypto_profile_ikev2` VARCHAR(150) NOT NULL,
  `require_cookie_ikev2` VARCHAR(255) NOT NULL,
  `local_address_ip` VARCHAR(40) NOT NULL,
  `interface` VARCHAR(45) NOT NULL,
  `type_authentication` VARCHAR(45) NOT NULL,
  `pre_shared_key` MEDIUMTEXT NOT NULL NOT NULL,
  `allow_id_payload_mismatch` VARCHAR(45) NOT NULL,
  `local_certificate` VARCHAR(45) NOT NULL,
  `certificate_profile` VARCHAR(45) NOT NULL,
  `strict_validation_revocation` VARCHAR(45) NOT NULL,
  `hash_and_url` VARCHAR(10) NOT NULL,
  `base_url` MEDIUMTEXT NOT NULL,
  `nat_traversal` VARCHAR(10) NOT NULL,
  `passive_mode` VARCHAR(10) NOT NULL,
  `fragmentation` VARCHAR(10) NOT NULL,
  `peer_ip_type` VARCHAR(40) NOT NULL,
  `peer_ip_address` VARCHAR(40) NOT NULL,
  `local_id` VARCHAR(255) NOT NULL,
  `local_id_type` VARCHAR(255) NOT NULL,
  `peer_id` VARCHAR(255) NOT NULL,
  `peer_id_type` VARCHAR(40) NOT NULL,
  `peer_id_matching` VARCHAR(40) NOT NULL,
  `address_type` VARCHAR(10) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `ipsec_crypto_profiles`
--

-- DROP TABLE IF EXISTS `ipsec_crypto_profiles`;
CREATE TABLE `ipsec_crypto_profiles` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `encryption` MEDIUMTEXT NOT NULL,
  `hash` MEDIUMTEXT NOT NULL,
  `dh_group` MEDIUMTEXT NOT NULL,
  `protocol` MEDIUMTEXT NOT NULL,
  `seconds` INT(11) NOT NULL,
  `minutes` INT(11) NOT NULL,
  `hours` INT(11) NOT NULL,
  `days` INT(11) NOT NULL,
  `kb` INT(11) NOT NULL,
  `mb` INT(11) NOT NULL,
  `gb` INT(11) NOT NULL,
  `tb` INT(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `ipsec_tunnel`
--

-- DROP TABLE IF EXISTS `ipsec_tunnel`;
CREATE TABLE `ipsec_tunnel` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `anti_replay` VARCHAR(30) NOT NULL,
  `copy_tos` VARCHAR(30) NOT NULL,
  `tunnel_monitor` VARCHAR(30) NOT NULL,
  `destination_ip` VARCHAR(40) NOT NULL,
  `tunnel_monitor_profile` VARCHAR(100) NOT NULL,
  `tunnel_interface` VARCHAR(100) NOT NULL,
  `address_type` VARCHAR(10) NOT NULL,
  `type_tunnel` VARCHAR(100) NOT NULL,
  `ike_gateway` VARCHAR(100) NOT NULL,
  `ipsec_crypto_profile` VARCHAR(100) NOT NULL,
  `protocol` VARCHAR(10) NOT NULL,
  `authentication` MEDIUMTEXT NOT NULL,
  `key_auth` MEDIUMTEXT NOT NULL,
  `encryption` MEDIUMTEXT NOT NULL,
  `key_encry` MEDIUMTEXT NOT NULL,
  `local_address_ip` VARCHAR(40) NOT NULL,
  `interface` VARCHAR(45) NOT NULL,
  `peer_ip_address` VARCHAR(40) NOT NULL,
  `local_spi` VARCHAR(45) NOT NULL,
  `remote_spi` VARCHAR(40) NOT NULL,
  `external_ca` VARCHAR(10) NOT NULL,
  `certificate_profile` VARCHAR(100) NOT NULL,
  `local_certificate` VARCHAR(100) NOT NULL,
  `publish_connected_routes` VARCHAR(10) NOT NULL,
  `portal_address` VARCHAR(400) NOT NULL,
  `publish_routes` VARCHAR(600) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  `disabled` varchar(10) DEFAULT 'no',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `gre_tunnel`;
CREATE TABLE `gre_tunnel` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `local_address_ip` VARCHAR(40) NOT NULL,
  `interface` VARCHAR(45) NOT NULL,
  `peer_ip_address` VARCHAR(40) NOT NULL,
  `keep_alive` VARCHAR(3) NOT NULL,
  `keep_alive_interval` INT(3) DEFAULT '10',
  `keep_alive_retry` INT(3) DEFAULT '3',
  `keep_alive_hold_timer` INT(3) DEFAULT '5',
  `tunnel_interface` VARCHAR(100) NOT NULL,
  `copy_tos` VARCHAR(30) NOT NULL,
  `dummy` int(1)  DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `proxy_id_ipsec_tunnel`
--

-- DROP TABLE IF EXISTS `proxy_id_ipsec_tunnel`;
CREATE TABLE `proxy_id_ipsec_tunnel` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `name_ext` VARCHAR(100),
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `template` INT(11) NOT NULL,
  `ipsec_tunnel_id` INT(11) NOT NULL,
  `protocol` VARCHAR(30) NOT NULL,
  `local_port` VARCHAR(30) NOT NULL,
  `remote_port` VARCHAR(30) NOT NULL,
  `number` VARCHAR(40) NOT NULL,
  `local` VARCHAR(40) NOT NULL,
  `remote` VARCHAR(40) NOT NULL,
  `type` VARCHAR(10) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
ALTER TABLE proxy_id_ipsec_tunnel ADD CONSTRAINT unique_row UNIQUE (vsys,source,template,ipsec_tunnel_id, protocol, local_port, remote_port, number, local, remote, type);



--
-- Table structure for table `interface_management_profile`
--

-- DROP TABLE IF EXISTS `interface_management_profile`;
CREATE TABLE `interface_management_profile` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `permitted_ip` mediumtext NOT NULL,
  `http` varchar(3) NOT NULL DEFAULT 'no',
  `https` varchar(3) NOT NULL DEFAULT 'no',
  `http_ocsp` varchar(3) NOT NULL DEFAULT 'no',
  `ssh` varchar(3) NOT NULL DEFAULT 'no',
  `snmp` varchar(3) NOT NULL DEFAULT 'no',
  `userid_service` varchar(3) NOT NULL DEFAULT 'no',
  `userid_syslog_listener_ssl` varchar(3) NOT NULL DEFAULT 'no',
  `userid_syslog_listener_udp` varchar(3) NOT NULL DEFAULT 'no',
  `ping` varchar(3) NOT NULL DEFAULT 'no',
  `response_pages` varchar(3) NOT NULL DEFAULT 'no',
  `telnet` varchar(3) NOT NULL DEFAULT 'no',
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `index1` (`source`),
  KEY `index2` (`name`),
  KEY `index3` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `interfaces`
--

-- DROP TABLE IF EXISTS `interfaces`;
CREATE TABLE `interfaces` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template` int(11) NOT NULL,
  `name` varchar(45) NOT NULL,
  `name_ext` varchar(45),
  `map_name` varchar(45) NOT NULL,
  `type` varchar(15) NOT NULL DEFAULT 'layer3',
  `link_speed` varchar(10) NOT NULL DEFAULT 'auto',
  `link_duplex` varchar(10) NOT NULL DEFAULT 'auto',
  `link_state` varchar(10) NOT NULL DEFAULT 'auto',
  `ipv6` text NOT NULL,
  `untagged_sub_interface` varchar(3) NOT NULL DEFAULT 'no',
  `adjust_tcp_mss` varchar(3) NOT NULL DEFAULT 'no',
  `interface_management_profile` varchar(31) NOT NULL DEFAULT 'None',
  `unitname` varchar(45) NOT NULL,
  `unittag` int(5) NOT NULL,
  `map_unitname` varchar(45) NOT NULL,
  `map_unittag` int(5) NOT NULL,
  `unitipaddress` TEXT NOT NULL,
  `comment` varchar(1023) NOT NULL,
  `vr_id` int(11) NOT NULL,
  `map_vr` varchar(31) NOT NULL,
  `zone` varchar(255) NOT NULL,
  `mtu` int(5) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `arp` text NOT NULL,
  `aggregate_group` varchar(45) NOT NULL,
  `vlan` varchar(31) NOT NULL,
  `ppoe` text NOT NULL,
  `dhcp_client` text NOT NULL,
  `media` varchar(45) NOT NULL,
  `invalid` int(1) NOT NULL DEFAULT '0',
  `vwire_id` int(11) NOT NULL,
  `ipv4_type` varchar(45) NOT NULL DEFAULT 'static',
  `dhcp_client_default_route_metric` int(11) NOT NULL,
  `dhcp_client_enable` varchar(3) NOT NULL DEFAULT 'yes',
  `dhcp_client_create_default_route` varchar(3) NOT NULL DEFAULT 'yes',
  `lacp_port_priority` int(11) NOT NULL,
  `lacp` text NOT NULL,
  `ip_classifier` text NOT NULL,
  `netflow_profile` varchar(31) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `log_card` text NOT NULL,
  `lldp` mediumtext NOT NULL,
  `ndpproxy` mediumtext NOT NULL,
  `ipv4_mss_adjustment` int(11) NOT NULL,
  `ipv6_mss_adjustment` int(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`template`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `known_traffic_by_app`
--

-- DROP TABLE IF EXISTS `known_traffic_by_app`;
CREATE TABLE `known_traffic_by_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `rule_lid` int(11) NOT NULL,
  `app` varchar(255) NOT NULL,
  `dst` varchar(45) NOT NULL,
  `dport` int(11) NOT NULL,
  `proto` varchar(45) NOT NULL,
  `from` varchar(16) NOT NULL,
  `to` varchar(16) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `packets` int(11) NOT NULL,
  `bytes` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index2` (`source`),
  KEY `index3` (`vsys`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `log_settings`
--

-- DROP TABLE IF EXISTS `log_settings`;
CREATE TABLE `log_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63),
  `xml` text,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `template` int(11) DEFAULT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`source`),
  KEY `index3` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `logs`
--

-- DROP TABLE IF EXISTS `logs`;
CREATE TABLE `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(45) NOT NULL,
  `source` varchar(45) NOT NULL,
  `level` int(11) NOT NULL,
  `task` varchar(50) NOT NULL,
  `message` text NOT NULL,
  `action` text NOT NULL,
  `fixed` int(1) NOT NULL DEFAULT '0',
  `datetime` datetime NOT NULL,
  `obj_type` varchar(75) NOT NULL,
  `obj_id` int(11) NOT NULL,
  `obj_table` varchar(75) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `monitor_profile`
--

-- DROP TABLE IF EXISTS `monitor_profile`;
CREATE TABLE `monitor_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `m_action` varchar(45) NOT NULL,
  `interva` int(5) NOT NULL,
  `threshold` int(5) NOT NULL,
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`template`,`name`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `nat_rules`
--

-- DROP TABLE IF EXISTS `nat_rules`;
CREATE TABLE `nat_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63),
  `description` varchar(255) NOT NULL,
  `target` text NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `disabled` int(1) DEFAULT '0',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `tp_sat_bidirectional` int(1) DEFAULT '0',
  `op_zone_to` varchar(255) NOT NULL,
  `op_to_interface` varchar(45) DEFAULT 'any',
  `is_dat` int(1) NOT NULL,
  `op_service_lid` int(11) NOT NULL,
  `op_service_table` varchar(45) NOT NULL,
  `tp_sat_type` varchar(45) NOT NULL,
  `tp_sat_address_type` varchar(20) NOT NULL,
  `tp_sat_interface` varchar(45) NOT NULL,
  `tp_sat_ipaddress` varchar(40) NOT NULL,
  `tp_dat_port` int(11) NOT NULL,
  `tp_dat_address_lid` int(11) NOT NULL,
  `tp_dat_address_table` varchar(45) NOT NULL,
  `implicit` int(1) NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL,
  `tag` text NOT NULL,
  `active_active_device_binding` varchar(7) NOT NULL,
  `nat_type` varchar(45) DEFAULT 'ipv4',
  `tp_sat_interface_fallback` varchar(45) NOT NULL,
  `tp_sat_ipaddress_fallback` varchar(45) NOT NULL,
  `tp_fallback_type` varchar(45) NOT NULL DEFAULT 'None',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`position`),
  KEY `index3` (`lid`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `nat_rules_dst`
--

-- DROP TABLE IF EXISTS `nat_rules_dst`;
CREATE TABLE `nat_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `counter` varchar(45) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`vsys`),
  KEY `index4` (`source`),
  KEY `index5` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `nat_rules_from`
--

-- DROP TABLE IF EXISTS `nat_rules_from`;
CREATE TABLE `nat_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `nat_rules_src`
--

-- DROP TABLE IF EXISTS `nat_rules_src`;
CREATE TABLE `nat_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`source`,`vsys`,`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `nat_rules_tag`
--

-- DROP TABLE IF EXISTS `nat_rules_tag`;
CREATE TABLE `nat_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `nat_rules_translated_address`
--

-- DROP TABLE IF EXISTS `nat_rules_translated_address`;
CREATE TABLE `nat_rules_translated_address` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `nat_rules_translated_address_fallback`
--

-- DROP TABLE IF EXISTS `nat_rules_translated_address_fallback`;
CREATE TABLE `nat_rules_translated_address_fallback` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `netscreen_dip`
--

-- DROP TABLE IF EXISTS `netscreen_dip`;
CREATE TABLE `netscreen_dip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `unitname` varchar(45) NOT NULL,
  `dip` int(11) NOT NULL,
  `startip` varchar(100) NOT NULL,
  `endip` varchar(100) NOT NULL,
  `tp_sat_type` varchar(25) NOT NULL DEFAULT 'dynamic-ip-and-port',
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`dip`,`source`,`template`),
  KEY `index2` (`unitname`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `netscreen_dip_mapping`
--

-- DROP TABLE IF EXISTS `netscreen_dip_mapping`;
CREATE TABLE `netscreen_dip_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `dip_type` varchar(45) NOT NULL,
  `dip` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `netscreen_natdst`
--

-- DROP TABLE IF EXISTS `netscreen_natdst`;
CREATE TABLE `netscreen_natdst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `ipaddress` varchar(100) NOT NULL,
  `port` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`rule_lid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `ocsp_responder`
--

-- DROP TABLE IF EXISTS `ocsp_responder`;
CREATE TABLE `ocsp_responder` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `other_rules`
--

-- DROP TABLE IF EXISTS `other_rules`;
CREATE TABLE `other_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `type` varchar(45) NOT NULL,
  `xml` longtext NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `output_mapping`
--

-- DROP TABLE IF EXISTS `output_mapping`;
CREATE TABLE `output_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `xml_initial` LONGTEXT NOT NULL,
  `xml_final` LONGTEXT NOT NULL,
  `state` varchar(45) NOT NULL,
  `sync` int(1) NOT NULL DEFAULT '0',
  `object` varchar(100) NOT NULL,
  `action` varchar(45) NOT NULL DEFAULT 'set',
  `xpath` text NOT NULL,
  `output` mediumtext NOT NULL,
  `name` varchar(255) NOT NULL,
  `whereto` varchar(250) NOT NULL,
  `dst` varchar(250) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `override`
--

-- DROP TABLE IF EXISTS `override`;
CREATE TABLE `override` (
  `id` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `xml` LONGTEXT NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `panorama`
--

-- DROP TABLE IF EXISTS `panorama`;
CREATE TABLE `panorama` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `xml` LONGTEXT NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `pending_tasks`
--

-- DROP TABLE IF EXISTS `pending_tasks`;
CREATE TABLE `pending_tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action` varchar(45) NOT NULL DEFAULT 'merge',
  `filename` varchar(255) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `type` varchar(45) NOT NULL,
  `element` varchar(255) NOT NULL DEFAULT 'all',
  `map_filename` varchar(255) NOT NULL,
  `map_vsys` varchar(45) NOT NULL,
  `template` int(11) NOT NULL,
  `map_template` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `pending_tasks`
--

LOCK TABLES `pending_tasks` WRITE;
/*!40000 ALTER TABLE `pending_tasks` DISABLE KEYS */;
/*!40000 ALTER TABLE `pending_tasks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `phase2_known_apps`
--

-- DROP TABLE IF EXISTS `phase2_known_apps`;
CREATE TABLE `phase2_known_apps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_id` int(11) NOT NULL,
  `name` varchar(45) NOT NULL,
  `port` varchar(45) NOT NULL,
  `default_port` varchar(355) NOT NULL,
  `requires` varchar(45) NOT NULL,
  `recommended` varchar(45) NOT NULL,
  `recommended_requires` varchar(355) NOT NULL,
  `app_default` tinyint(1) NOT NULL,
  `rule_id` int(11) NOT NULL,
  `rule_old_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `policy_filters`
--

-- DROP TABLE IF EXISTS `policy_filters`;
CREATE TABLE `policy_filters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filter_name` varchar(355) NOT NULL,
  `filter_column` varchar(45) NOT NULL,
  `operator` varchar(45) NOT NULL,
  `search` varchar(355) NOT NULL,
  `and_or` varchar(3) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `rules_lid` longtext NOT NULL,
  `active` INT(11) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `policy_filters_nat`
--

-- DROP TABLE IF EXISTS `policy_filters_nat`;
CREATE TABLE `policy_filters_nat` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filter_name` varchar(355) NOT NULL,
  `filter_column` varchar(45) NOT NULL,
  `operator` varchar(45) NOT NULL,
  `search` varchar(355) NOT NULL,
  `and_or` varchar(3) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `active` INT(11) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `profiles`
--

-- DROP TABLE IF EXISTS `profiles`;
CREATE TABLE `profiles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  `checkit` int(1),
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`name`),
  KEY `index2` (`type`,`vsys`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `profiles_groups`
--

-- DROP TABLE IF EXISTS `profiles_groups`;
CREATE TABLE `profiles_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` text,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  `checkit` int(1),
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`name`,`vsys`),
  KEY `index2` (`vsys`,`type`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `project_status`
--

-- DROP TABLE IF EXISTS `project_status`;
CREATE TABLE `project_status` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `datetime` datetime NOT NULL,
  `project` varchar(255) NOT NULL,
  `percentage` decimal(5,2) DEFAULT '0.00',
  `message` varchar(150) DEFAULT 'Working',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`project`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `qos_interface`
--

-- DROP TABLE IF EXISTS `qos_interface`;
CREATE TABLE `qos_interface` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`template`,`source`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `qos_profile`
--

-- DROP TABLE IF EXISTS `qos_profile`;
CREATE TABLE `qos_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`template`,`name`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `regions`
--

-- DROP TABLE IF EXISTS `regions`;
CREATE TABLE `regions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `xml` text,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `latitude` varchar(45) NOT NULL,
  `longitude` varchar(45) NOT NULL,
  `address` text NOT NULL,
  `used` int(1) DEFAULT '0',
  `dummy` int(1) DEFAULT '0',
  `checkit` int(1),
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`source`),
  KEY `index3` (`vsys`),
  KEY `index4` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `reports`
--

-- DROP TABLE IF EXISTS `reports`;
CREATE TABLE `reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `name_ext` varchar(64),
  `type` text NOT NULL,
  `period` varchar(100) NOT NULL,
  `topn` int(10) NOT NULL,
  `topm` int(10) NOT NULL,
  `caption` varchar(1024) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `starttime` varchar(100) NOT NULL,
  `endtime` varchar(100) NOT NULL,
  `query` mediumtext NOT NULL,
  `frequency` varchar(255) NOT NULL,
  `description` varchar(1023) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `response_pages`
--

-- DROP TABLE IF EXISTS `response_pages`;
CREATE TABLE `response_pages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `type` varchar(50) NOT NULL,
  `html` TEXT(21845) NOT NULL,
  `name` varchar(45) NOT NULL,
  `name_ext` varchar(45),
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`vsys`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `routes_static`
--

-- DROP TABLE IF EXISTS `routes_static`;
CREATE TABLE `routes_static` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vr_id` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `ip_version` varchar(5) NOT NULL DEFAULT 'v4',
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `destination` varchar(45) NOT NULL,
  `destination_member_lid` int(20) NOT NULL,
  `tointerface` varchar(45) NOT NULL,
  `nexthop` varchar(45) NOT NULL,
  `nexthop_value` varchar(45) NOT NULL DEFAULT 'None',
  `nexthop_value_member_lid` int(20) NOT NULL,
  `metric` int(5) NOT NULL DEFAULT '10',
  `admin_dist` int(5) NOT NULL,
  `option_no_install` int(1) NOT NULL DEFAULT '0',
  `zone` varchar(255) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `route_table` varchar(255) NOT NULL DEFAULT 'unicast',
  `bfd_profile` varchar(255) NOT NULL DEFAULT 'None',
  `pm_enable` varchar(45) NOT NULL DEFAULT 'no',
  `pm_failure_condition` varchar(45) NOT NULL DEFAULT 'any',
  `pm_hold_time` int(10) NOT NULL DEFAULT '2',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `schedules`
--

-- DROP TABLE IF EXISTS `schedules`;
CREATE TABLE `schedules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` text,
  `type` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `devicegroup` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`vsys`,`type`,`name`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `search_replace`
--

-- DROP TABLE IF EXISTS `search_replace`;
CREATE TABLE `search_replace` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `lid` int(11) NOT NULL,
  `table_name_lid` varchar(45) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `name` varchar(100) NOT NULL,
  `locate` varchar(45) NOT NULL,
  `position` varchar(45) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `object_replace` varchar(45) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules`
--

-- DROP TABLE IF EXISTS `security_rules`;
CREATE TABLE `security_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `position` int(11) NOT NULL,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(63) NOT NULL,
  `negate_source` int(1) DEFAULT '0',
  `negate_destination` int(1) DEFAULT '0',
  `description` varchar(1024) NOT NULL,
  `action` varchar(45) NOT NULL,
  `schedule` varchar(45) NOT NULL,
  `disabled` int(1) DEFAULT '0',
  `log_start` int(1) DEFAULT '0',
  `log_end` int(1) DEFAULT '1',
  `log_forwarding` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `dsri` int(1) DEFAULT '0',
  `target` text NOT NULL,
  `checkit` int(1) DEFAULT '0',
  `migrate` int(1) DEFAULT '1',
  `counter` int(45) NOT NULL,
  `qos` varchar(255) DEFAULT 'None',
  `profile_type` varchar(45) NOT NULL,
  `profile_group` varchar(255) NOT NULL,
  `qos_value` varchar(45) NOT NULL,
  `tag` text NOT NULL,
  `preorpost` int(1) NOT NULL DEFAULT '0',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `blocked` int(1) NOT NULL DEFAULT '0',
  `rule_type` varchar(45) NOT NULL DEFAULT 'universal',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `icmp_unreachable` varchar(45) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  `uuid` varchar(255) DEFAULT '',
  `group_tag_id` int(11) NOT NULL,
  `target_negate` varchar(3) NOT NULL DEFAULT 'no',
  `ml` int(1) NOT NULL DEFAULT '0',
  `re` int(1) NOT NULL DEFAULT '0',
  `re_users` int(1) NOT NULL DEFAULT '0',
  `re_app_default` int(1) NOT NULL DEFAULT '0',
  `layer` int(1) NOT NULL DEFAULT '4',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`lid`),
  KEY `index3` (`position`),
  KEY `index4` (`vsys`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `security_rules_app`
--

-- DROP TABLE IF EXISTS `security_rules_app`;
CREATE TABLE `security_rules_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` varchar(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_categories`
--

-- DROP TABLE IF EXISTS `security_rules_categories`;
CREATE TABLE `security_rules_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_dst`
--

-- DROP TABLE IF EXISTS `security_rules_dst`;
CREATE TABLE `security_rules_dst` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_from`
--

-- DROP TABLE IF EXISTS `security_rules_from`;
CREATE TABLE `security_rules_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `security_rules_hip`
--

-- DROP TABLE IF EXISTS `security_rules_hip`;
CREATE TABLE `security_rules_hip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  `name` varchar(45) NOT NULL,
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_profiles`
--

-- DROP TABLE IF EXISTS `security_rules_profiles`;
CREATE TABLE `security_rules_profiles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `member_lid` varchar(255) NOT NULL,
  `rule_lid` varchar(45) NOT NULL,
  `type` varchar(150) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`type`),
  KEY `index4` (`table_name`,`member_lid`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_src`
--

-- DROP TABLE IF EXISTS `security_rules_src`;
CREATE TABLE `security_rules_src` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_srv`
--

-- DROP TABLE IF EXISTS `security_rules_srv`;
CREATE TABLE `security_rules_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `counter` int(45) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`member_lid`,`table_name`),
  KEY `index5` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_tag`
--

-- DROP TABLE IF EXISTS `security_rules_tag`;
CREATE TABLE `security_rules_tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_to`
--

-- DROP TABLE IF EXISTS `security_rules_to`;
CREATE TABLE `security_rules_to` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(255) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `security_rules_usr`
--

-- DROP TABLE IF EXISTS `security_rules_usr`;
CREATE TABLE `security_rules_usr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) DEFAULT 'vsys1',
  `name` varchar(1023) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `devicegroup` varchar(255) DEFAULT 'default',
  `counter` int(45) NOT NULL,
  `from_log` varchar(10) DEFAULT 'false',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index3` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `security_rules_hits`;
CREATE TABLE `security_rules_hits` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) NOT NULL,
  `rule_name` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) unsigned NOT NULL,
  `hit_count` varchar(255) DEFAULT NULL,
  `hit_last` datetime DEFAULT NULL ,
  `hit_first` datetime DEFAULT NULL ,
  `last_reset` datetime DEFAULT NULL ,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `server_profile`
--

-- DROP TABLE IF EXISTS `server_profile`;
CREATE TABLE `server_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `type` varchar(45) NOT NULL,
  `name` varchar(31) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `services`
--

-- DROP TABLE IF EXISTS `services`;
CREATE TABLE `services` (
  `id` int(11)                      NOT NULL                  AUTO_INCREMENT,
  `name` varchar(255)               NOT NULL  DEFAULT '',
  `name_ext` varchar(255)           NOT NULL  DEFAULT '',
  `checkit` int(1)                            DEFAULT '0',
  `used` int(1)                               DEFAULT '0',
  `vsys` varchar(31)                          DEFAULT 'vsys1',
  `devicegroup` varchar(255)                  DEFAULT 'default',
  `type` varchar(45)                NOT NULL  DEFAULT '',
  `description` varchar(1023)       NOT NULL  DEFAULT '',
  `sport` varchar(1023)              NOT NULL  DEFAULT '',
  `dport` varchar(1023)              NOT NULL  DEFAULT '',
  `protocol` varchar(100)                     DEFAULT 'tcp',
  `icmp` int(1)                               DEFAULT '0',
  `source` varchar(255)             NOT NULL  DEFAULT '',
  `tag` text                        NOT NULL  DEFAULT '',
  `invalid` int(1)                  NOT NULL  DEFAULT '0',
  `modified` int(1)                 NOT NULL  DEFAULT '1',
  `vtype` varchar(45)               NOT NULL  DEFAULT '',
  `dummy` int(1)                    NOT NULL  DEFAULT '0',
  `disable_override` varchar(3)     NOT NULL  DEFAULT '',
  `app` varchar(255)                NOT NULL  DEFAULT '',
  `merge_as_primary` INT(1)         NOT NULL  DEFAULT 0,
  `override` varchar(3)             NOT NULL  DEFAULT 'no',
  `timeout` varchar(255)            NOT NULL  DEFAULT '',
  `halfclose_timeout` varchar(255)  NOT NULL  DEFAULT '',
  `timewait_timeout` varchar(255)   NOT NULL  DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`name`),
  KEY `index3` (`name_ext`),
  KEY `index4` (`vsys`),
  #KEY `index6` (`dport`,`protocol`),
  KEY `index5` (`source`),
  KEY `index7` (`name`,`vsys`,`source`),
  KEY `index8` (`name_ext`,`vsys`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `services_groups`
--

-- DROP TABLE IF EXISTS `services_groups`;
CREATE TABLE `services_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `devicegroup` varchar(255) DEFAULT 'default',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `member` varchar(255) NOT NULL,
  `member_lid` int(20) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index2` (`member`),
  KEY `index3` (`vsys`),
  KEY `index1` (`lid`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `services_groups_id`
--

-- DROP TABLE IF EXISTS `services_groups_id`;
CREATE TABLE `services_groups_id` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `used` int(1) DEFAULT '0',
  `checkit` int(1) DEFAULT '0',
  `devicegroup` varchar(255) DEFAULT 'default',
  `vsys` varchar(31) DEFAULT 'vsys1',
  `type` varchar(100) NOT NULL DEFAULT 'static',
  `source` int(11) NOT NULL,
  `description` varchar(1023) NOT NULL,
  `tag` text NOT NULL,
  `filter` text NOT NULL,
  `invalid` int(1) NOT NULL DEFAULT '0',
  `modified` int(1) NOT NULL DEFAULT '1',
  `dummy` int(1) DEFAULT '0',
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`name`),
  KEY `index2` (`name_ext`),
  KEY `index3` (`vsys`),
  KEY `index4` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `shared_authentication_profile`
--

-- DROP TABLE IF EXISTS `shared_authentication_profile`;
CREATE TABLE `shared_authentication_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `shared_authentication_sequence`
--

-- DROP TABLE IF EXISTS `shared_authentication_sequence`;
CREATE TABLE `shared_authentication_sequence` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `shared_certificate`
--

-- DROP TABLE IF EXISTS `shared_certificate`;
CREATE TABLE `shared_certificate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `shared_certificate_profile`
--

-- DROP TABLE IF EXISTS `shared_certificate_profile`;
CREATE TABLE `shared_certificate_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255),
  `template` int(11) NOT NULL,
  `xml` mediumtext NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `split_rules_unknown`
--

-- DROP TABLE IF EXISTS `split_rules_unknown`;
CREATE TABLE `split_rules_unknown` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `original_rule_lid` int(11) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- Table structure for table `relation_lid_rule_name`
--

-- DROP TABLE IF EXISTS `relation_lid_rule_name`;
CREATE TABLE `relation_lid_rule_name` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `rule_lid` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `subcategory`
--

-- DROP TABLE IF EXISTS `subcategory`;
CREATE TABLE `subcategory` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `subcategory`
--

LOCK TABLES `subcategory` WRITE;
/*!40000 ALTER TABLE `subcategory` DISABLE KEYS */;
INSERT INTO subcategory VALUES ('1', 'file-sharing'), ('2', 'management'), ('3', 'erp-crm'), ('4', 'email'), ('5', 'social-networking'), ('6', 'web-posting'), ('7', 'software-update'), ('8', 'ip-protocol'),
('9', 'gaming'), ('10', 'audio-streaming'), ('11', 'database'), ('12', 'voip-video'), ('13', 'auth-service'), ('14', 'general-business'), ('15', 'photo-video'), ('16', 'internet-conferencing'), ('17', 'remote-access'), ('18', 'internet-utility'),
('19', 'office-programs'), ('20', 'storage-backup'), ('21', 'instant-messaging'), ('22', 'proxy'), ('23', 'infrastructure'), ('24', 'social-business'), ('25', 'encrypted-tunnel'), ('26', 'routing');
/*!40000 ALTER TABLE `subcategory` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tag`
--

-- DROP TABLE IF EXISTS `tag`;
CREATE TABLE `tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(127) NOT NULL,
  `name_ext` varchar(127) NOT NULL,
  `color` varchar(45) NOT NULL DEFAULT 'None',
  `comments` varchar(1023) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `devicegroup` varchar(255) NOT NULL DEFAULT 'default',
  `modified` int(1) NOT NULL DEFAULT '1',
  `vtype` varchar(45) NOT NULL,
  `dummy` int(1) NOT NULL DEFAULT '0',
  `checkit` int(1),
  `disable_override` varchar(3) NOT NULL DEFAULT '',
  `merge_as_primary` INT(1) NOT NULL DEFAULT 0,
  `used` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `tag_relations`
--

-- DROP TABLE IF EXISTS `tag_relations`;
CREATE TABLE `tag_relations` (
 `id` INT NOT NULL AUTO_INCREMENT,
 `table_name` VARCHAR(255) NOT NULL,
 `member_lid` INT NOT NULL,
 `tag_id` INT NOT NULL,
 PRIMARY KEY (`id`)
 )ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `tag_colors`
--

-- DROP TABLE IF EXISTS `tag_colors`;
CREATE TABLE `tag_colors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `color` varchar(45) NOT NULL,
  `version` varchar(45) NOT NULL,
  PRIMARY KEY (`id`)
)ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `tag_colors` WRITE;
/*!40000 ALTER TABLE `tag_colors` DISABLE KEYS */;
INSERT INTO tag_colors VALUES
('1', 'color1', '#CD383F', '6'),
('2', 'color2', '#72A392', '6'),
('3', 'color3', '#569BBD', '6'),
('4', 'color4', '#EBD722', '6'),
('5', 'color5', '#C27D2A', '6'),
('6', 'color6', '#FF6A00', '6'),
('7', 'color7', '#7D3953', '6'),
('8', 'color8', '#5B6F7B', '6'),
('9', 'color9', '#C9D6A6', '6'),
('10', 'color10', '#8AD3DF', '6'),
('11', 'color11', '#C2D1D3', '6'),
('12', 'color12', '#80A1B6', '6'),
('13', 'color13', '#C1D72F', '6'),
('14', 'color14', '#000000', '6'),
('15', 'color15', '#FFC425', '6'),
('16', 'color16', '#918A75', '6'),
('17', 'color17', '#97a730', '8.1'),
('19', 'color19', '#c1254a', '8.1'),
('20', 'color20', '#fd682f', '8.1'),
('21', 'color21', '#fdad4d', '8.1'),
('22', 'color22', '#61a678', '8.1'),
('23', 'color23', '#70dae6', '8.1'),
('24', 'color24', '#4d98ce', '8.1'),
('25', 'color25', '#6da2b8', '8.1'),
('26', 'color26', '#07488a', '8.1'),
('27', 'color27', '#4773e3', '8.1'),
('28', 'color28', '#8c91c6', '8.1'),
('29', 'color29', '#7670c6', '8.1'),
('30', 'color30', '#6459b5', '8.1'),
('31', 'color31', '#8e4bb1', '8.1'),
('32', 'color32', '#d76ebd', '8.1'),
('33', 'color33', '#d76ebd', '8.1'),
('34', 'color34', '#e19dd1', '8.1'),
('35', 'color35', '#eab1d6', '8.1'),
('36', 'color36', '#fecba7', '8.1'),
('37', 'color37', '#fd92a5', '8.1'),
('38', 'color38', '#f457a6', '8.1'),
('39', 'color39', '#b93784', '8.1'),
('40', 'color40', '#c8363a', '8.1'),
('41', 'color41', '#aa6647', '8.1'),
('42', 'color42', '#b74e4b', '8.1'),
('43', 'None', '', '8.1'),
('44', '', '', '8.1');
/*!40000 ALTER TABLE `tag_colors` ENABLE KEYS */;
UNLOCK TABLES;
/* El 18 no existe! */


--
-- Table structure for table `technology`
--

-- DROP TABLE IF EXISTS `technology`;
CREATE TABLE `technology` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `technology`
--

LOCK TABLES `technology` WRITE;
/*!40000 ALTER TABLE `technology` DISABLE KEYS */;
INSERT INTO technology VALUES ('1', 'peer-to-peer'), ('2', 'client-server'), ('3', 'browser-based'), ('4', 'network-protocol');
/*!40000 ALTER TABLE `technology` ENABLE KEYS */;
UNLOCK TABLES;



DROP TABLE IF EXISTS `templates_stacks_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `templates_stacks_id` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(31),
  `description` varchar(255) NOT NULL,
  `devices` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `templates_mapping_id` int(11) NOT NULL,
  `default_vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `templates_stacks`;
CREATE TABLE `templates_stacks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(31),
  `description` varchar(255) NOT NULL,
  `devices` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `templates_mapping_id` int(11) NOT NULL,
  `lid` int(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `templates`
--

-- DROP TABLE IF EXISTS `templates`;
CREATE TABLE `templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(31),
  `description` varchar(255) NOT NULL,
  `multi_vsys` varchar(3) NOT NULL DEFAULT 'no',
  `operational_mode` varchar(10) NOT NULL DEFAULT 'normal',
  `vpn_disable_mode` varchar(3) NOT NULL DEFAULT 'no',
  `devices` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `templates_mapping_id` int(11) NOT NULL,
  `default_vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `templates_mapping`
--

-- DROP TABLE IF EXISTS `templates_mapping`;
CREATE TABLE `templates_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(63) NOT NULL,
  `name_ext` varchar(31),
  `filename` varchar(255) NOT NULL,
  `source` int(11) NOT NULL,
  `project` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`filename`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `tmp_calc_zone`
--

-- DROP TABLE IF EXISTS `tmp_calc_zone`;
CREATE TABLE `tmp_calc_zone` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `zone` mediumtext NOT NULL,
  `is_negated` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `tmp_dup_name_val`
--

-- DROP TABLE IF EXISTS `tmp_dup_name_val`;
CREATE TABLE `tmp_dup_name_val` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `lid` int(11) NOT NULL,
  `members` text NOT NULL,
  `table_name` varchar(45) NOT NULL,
  `name` varchar(255) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`members`(767),`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `tools_filters`
--

-- DROP TABLE IF EXISTS `tools_filters`;
CREATE TABLE `tools_filters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filter_name` VARCHAR(355) NOT NULL,
  `tools_where_columns_id` VARCHAR(255) NOT NULL,
  `tools_operator_id` VARCHAR(255) NOT NULL,
  `search` VARCHAR(355) NOT NULL,
  `tools_where_id` VARCHAR(355) NOT NULL,
  `tools_advanced_columns_id` VARCHAR(255) NOT NULL,
  `case_sensitive` INT(1) NOT NULL DEFAULT 0,
  `vsys` VARCHAR(31) NOT NULL,
  `source` INT(11) NOT NULL,
  `active` INT(1) NOT NULL DEFAULT 1,
  `tools_sql_id` INT(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



--
-- Table structure for table `tools_sql`
--

-- DROP TABLE IF EXISTS `tools_sql`;
CREATE TABLE `tools_sql` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `parent_id` int(11) NOT NULL,
  `name` varchar(45) NOT NULL,
  `filter_id` varchar(355) NOT NULL,
  `source` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1000;



--
-- Table structure for table `tools_where_columns`
--

-- DROP TABLE IF EXISTS `tools_where_columns`;
CREATE TABLE `tools_where_columns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `column_or_table_name` varchar(45) NOT NULL,
  `filter_type` varchar(45) NOT NULL,
  `recursive` varchar(45) NOT NULL,
  `order_by` FLOAT(3) NOT NULL,
  `tools_operator_id` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `tools_where_columns`
--

LOCK TABLES `tools_where_columns` WRITE;
/*!40000 ALTER TABLE `tools_where_columns` DISABLE KEYS */;
INSERT INTO tools_where_columns VALUES
('1', 'Name', 'name', '1', '', '1', '1,3,4,6,12,13'),
('2', 'Action', 'action', '1', '', '2', '4,6'),
('3', 'RuleID', 'id', '1', '', '3', '1,3,4,6,12,13'),
('4', 'Tag', 'tag_relations', '2', 'true', '4', '1,3,4,6,12,13'),
('5', 'From', 'security_rules_from', '2', 'false', '5', '1,3,4,6,12,13'),
('6', 'Source', 'security_rules_src', '2', 'true', '6', '1,2,3,4,5,6,7,8,12,13'),
('7', 'To', 'security_rules_to', '2', 'false', '7', '1,3,4,6,12,13'),
('8', 'Destination', 'security_rules_dst', '2', 'true', '8', '1,2,3,4,5,6,7,8,12,13'),
('9', 'Application', 'security_rules_app', '2', 'true', '9', '1,2,3,4,5,6,12,13'),
('10', 'Username', 'security_rules_usr', '2', 'false', '10', '1,3,4,6,12,13'),
('11', 'Service', 'security_rules_srv', '2', 'true', '11', '1,2,3,4,5,6,12,13'),
('12', 'Log Forwarding', 'log_forwarding', '1', '', '12', '1,3,4,6,12,13'),
('13', 'Schedule', 'schedule', '1', '', '13', '1,3,4,6,12,13'),
('14', 'Profile', 'security_rules_profiles', '2', 'true', '14', '1,2,3,4,5,6,12,13'),
('15', 'Description', 'description', '1', '', '15', '1,3,4,6,12,13'),
('19', '[TP] Source', 'nat_rules_translated_address', '2', 'true', '16', '1,2,3,4,5,6,7,8,12,13'),
('20', '[TP] Destination', 'tp_dat_address_lid', '2', 'false', '17', '1,2,3,4,5,6,7,8,12,13'),
('21', '[TP] Port', 'tp_dat_port', '2', 'false', '18', '1,3,4,6,12,13'),
('22', 'Port', 'dport', '', '', '19', '1,3,4,6,12,13'),
('23', 'Protocol', 'protocol', '1', '', '20', '1,3,4,6,12,13'),
('24', 'IP Address', 'ipaddress', '1', '', '21', '1,3,4,6,12,13'),
('25', 'Cidr', 'cidr', '1', '', '22', '1,3,4,6,12,13'),
('26', 'Members', 'members', '', '', '23', '1,3,4,6,12,13'),
('27', 'Dst Port', 'dport', '1', '', '24', '1,3,4,6,12,13'),
('28', 'Category', 'category', '1', '', '25', '1,3,4,6,12,13'),
('29', 'Subcategory', 'subcategory', '1', '', '26', '1,3,4,6,12,13'),
('30', 'Technology', 'technology', '1', '', '27', '1,3,4,6,12,13'),
('31', 'Risk', 'risk', '1', '', '28', '4,6'),
('32', 'Characteristics', '', '', '', '29', '1,3,4,6,12,13'),
('41', 'IP', 'address', '1', '', '30', '1,3,4,6,12,13'),
('42', 'Latitude', 'latitude', '1', '', '31', '1,3,4,6,12,13'),
('43', 'Longitude', 'longitude', '1', '', '32', '1,3,4,6,12,13'),
('44', 'Comments', 'comments', '1', '', '33', '1,3,4,6,12,13'),
('45', 'Vulnerability', '', '', '', '34', '1,3,4,6,12,13'),
('49', 'Type', 'type', '1', '', '35', '1,3,4,6,12,13'),
('50', 'Virtual Router', 'vr_id', '', '', '36', '1,3,4,6,12,13'),
('51', 'Zone', 'zone', '1', '', '37', '1,3,4,6,12,13'),
('52', 'Management Profile', 'interface_management_profile', '1', '', '38', '1,3,4,6,12,13'),
('53', 'Interface', 'interfaces', '1', '', '39', '1,3,4,6,12,13'),
('54', 'Interface1', '', '', '', '40', '1,3,4,6,12,13'),
('55', 'Interface2', '', '', '', '41', '1,3,4,6,12,13'),
('56', 'VLAN Interface', '', '', '', '42', '1,3,4,6,12,13'),
('57', 'IP Address', 'unitipaddress', '1', '', '43', '1,3,4,6,12,13'),
('66', 'Tag', 'security_rules_tag', '2', 'true', '44', '1,3,4,6,12,13'),
('67', 'Tag', 'nat_rules_tag', '2', 'true', '45', '1,3,4,6,12,13'),
('68', 'From', 'nat_rules_from', '2', 'false', '46', '1,3,4,6,12,13'),
('69', 'Source', 'nat_rules_src', '2', 'true', '47', '1,2,3,4,5,6,7,8,12,13'),
('70', 'To', 'op_zone_to', '1', 'false', '48', '1,3,4,6,12,13'),
('71', 'Destination', 'nat_rules_dst', '2', 'true', '49', '1,2,3,4,5,6,7,8,12,13'),
('72', 'Service', 'op_service_lid', '2', 'true', '50', '1,2,3,4,5,6,12,13'),
('73', '(Predefined) Invalid', 'invalid', '1', '', '51', ''),
('74', '(Predefined) Duplicated Name', 'duplicated_name', '', '', '52', ''),
('75', '(Predefined) Duplicated Name & Value', 'duplicated_name_value', '', '', '53', ''),
('76', '(Predefined) Duplicated Value', 'duplicated_value', '', '', '54', ''),
('77', '(Predefined) Groups with one member', 'groups_with_one_member', '', '', '55', ''),
('78', '(Predefined) Used', 'used', '', '', '57', ''),
('79', '(Predefined) Unused', 'unused', '', '', '58', ''),
('80', '(Predefined) Groups without Members', 'groups_without_members', '', '', '56', ''),
('81', '(Predefined) Invalid Rules', 'invalid', '', '', '59', ''),
('82', '(Predefined) Disabled', 'disabled', '', '', '60', ''),
('83', '(Predefined) Name is IP Address', 'name_is_ipaddress', '', '', '61', ''),

('84', '(Predefined) Select All', 'select_all', '', '', '84', ''),

('85', 'Type', 'type', '1', '', '22.1', '1,2,3,4,5,6,12,13'),
('86', '(BP) Rule Name is empty', 'invalid', '', '', '65', ''),
('87', '(BP) Tags are not used', 'tags_not_used', '', '', '66', ''),
('88', '(BP) Description is not populated', 'description_not_populated', '', '', '67', ''),
('89', '(BP) Source and Destination are both "any"', 'source_destination_any', '', '', '68', ''),
('90', '(BP) Service/port is "any"', 'service_any', '', '', '69', ''),
('91', '(BP) Log Start is enabled', 'log_start_enabled', '', '', '70', ''),
('92', '(BP) Log Forwarding is not enabled', 'log_forwarding_not_enabled', '', '', '71', ''),
('93', '(BP) Expired Schedule', 'expired_schedule', '', '', '72', ''),
('94', '(BP) Dsri is enabled', 'dsri_enabled', '', '', '73', ''),
('95', '(ML) Machine Learning is enabled', 'ml_enabled', '', '', '74', ''),
('96', '(Predefined) Rules with Warnings', 'rules_warnings', '', '', '62', ''),

('97', 'Tag', 'appoverride_rules_tag', '2', 'true', '15.1', '1,3,4,6,12,13'),
('98', 'From', 'appoverride_rules_from', '2', 'false', '15.2', '1,3,4,6,12,13'),
('99', 'Source', 'appoverride_rules_src', '2', 'true', '15.3', '1,2,3,4,5,6,7,8,12,13'),
('100', 'To', 'appoverride_rules_to', '2', 'false', '15.4', '1,3,4,6,12,13'),
('101', 'Destination', 'appoverride_rules_dst', '2', 'true', '15.5', '1,2,3,4,5,6,7,8,12,13'),
('102', 'Protocol', 'protocol', '1', '', '15.6', '1,3,4,6,12,13'),
('103', 'Port', 'port', '1', '', '15.7', '1,3,4,6,12,13'),
('104', 'Application', 'app_id', '2', 'true', '15.8', '1,2,3,4,5,6,7,8,12,13'),
('105', '(Predefined) Apps with Custom Timeout', 'apps_timeout', '', '', '83', ''),
('106', '(Predefined) Matched App Override', 'match_app_override', '', '', '62.1', ''),
('107', '(Predefined) Added Service Timeout', 'service_timeout', '', '', '62.2', ''),
('108', '(Predefined) Replaced App to Service Timeout', 'replaced_app_service_timeout', '', '', '62.3', ''),
('109', '(Predefined) Pre-rulebase', 'pre_rulebase', '', '', '62.4', ''),
('110', '(Predefined) Post-rulebase', 'post_rulebase', '', '', '62.5', ''),
('111', '(Predefined) Duplicated Name vs Groups', 'duplicated_name_vs_groups', '', '', '54.1', ''),
('112', '(Predefined) Enabled', 'enabled', '', '', '60.1', ''),
('113', '(ML) Rule Enrichment is Enabled', 're_enabled', '', '', '74.1', ''),
('114', '(Predefined) Invalid & Used', 'invalid_used', '', '', '61.1', ''),
('115', '(Predefined) Invalid Name', 'invalid_name', '', '', '61.2', ''),
('116', 'Target', 'security_rules_target', '2', 'false', '44.1', '1,3,4,6,12,13'),
('117', 'Checkpoint Target', 'target', '1', '', '44.2', '1,3,4,6,12,13'),
('118', '(Predefined) Ghost Objects', 'ghost_objects', '', '', '54.2', ''),
('119', '(Predefined) Bidirectional rules',     'bidirectional',        '','','60.2', ''),
('120', '(Predefined) NAT NoNat',               'nat_nonat',            '','','60.3', ''),
('121', '(Predefined) NAT Static',              'nat_static',           '','','60.4', ''),
('122', '(Predefined) NAT Dynamic IP',          'nat_dynamic_ip',       '','','60.5', ''),
('123', '(Predefined) NAT Dynamic IP and Port', 'nat_dynamic_ip_port',  '','','60.6', ''),
('124', 'Target', 'nat_rules_target', '2', 'false', '44.1', '1,3,4,6,12,13'),
('125', 'Target', 'appoverride_rules_target', '2', 'false', '15.9', '1,3,4,6,12,13'),
('126', '(Predefined) Rules with Users', 'rules_with_users', '', '', '62.6', ''),
('127', '(Predefined) Members "null"', 'rules_members_null', '', '', '62.7', ''),
('128', '(Predefined) Rules in Layer 4', 'getRulesLayer4', '','false', '62.51', ''),
('129', '(Predefined) Rules in Layer 7', 'getRulesLayer7', '','false', '62.52', ''),
('130', '(Predefined) Convertible to IP Object', 'getAddressNotInGroups', '','false', '58.1', ''),
('131', 'Interface', 'op_to_interface', '1', '', '50.1', '1,3,4,6,12,13'),
('132', '(Predefined) Rules with Hits', 'getRulesHits', '','false', '62.8', '14,15,16,17,18,19'),
('133', '(Predefined) Rules without Hits', 'getRulesNoHits',   '','false', '62.9', '14,15,16,17,18,19'),
('134', 'Affects the IP(s)',                    'getRulesAffectIPs','','false', '6.1',  '20,21,22'),
('135', '(Predefined) Rules with IPv6 objects', 'getRulesWithIPv6','','true' , '62.53','20,21,22'),
('136', '(Predefined) Not Ghost Objects', 'not_ghost_objects', '', '', '54.2', '');

/*!40000 ALTER TABLE `tools_where_columns` ENABLE KEYS */;
UNLOCK TABLES;

/* ¡¡ IMPORTANT !! ---> Filter (Predefined) Select All --> IS THE LAST FOREVER */

--
-- Table structure for table `tools_advanced_columns`
--

-- DROP TABLE IF EXISTS `tools_advanced_columns`;
CREATE TABLE `tools_advanced_columns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `tools_advanced_columns`
--

LOCK TABLES `tools_advanced_columns` WRITE;
/*!40000 ALTER TABLE `tools_advanced_columns` DISABLE KEYS */;
INSERT INTO tools_advanced_columns VALUES ('1', 'None'), ('2', 'Invalid'), ('3', 'Duplicated Names'), ('4', 'Duplicated Names & Value'),
('5', 'Duplicated Value'), ('6', 'Groups with one member'), ('7', 'Used'), ('8', 'Unused'), ('9', 'Groups without Members'),
('10', 'Invalid Rules'), ('11', 'Disabled');
/*!40000 ALTER TABLE `tools_advanced_columns` ENABLE KEYS */;
UNLOCK TABLES;


--
-- Table structure for table `tools_where`
--

-- DROP TABLE IF EXISTS `tools_where`;
CREATE TABLE `tools_where` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(45) NOT NULL,
  `table_name` VARCHAR(45) NOT NULL,
  `type` VARCHAR(45) NOT NULL,
  `image` VARCHAR(255) NOT NULL,
  `tools_where_columns_id` VARCHAR(255) NOT NULL,
  `tools_advanced_columns_id` VARCHAR(255) NOT NULL,
  `tools_operator_id` VARCHAR(255) NOT NULL,
  `order_by` FLOAT(3) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `tools_where`
--

LOCK TABLES `tools_where` WRITE;
/*!40000 ALTER TABLE `tools_where` DISABLE KEYS */;
INSERT INTO tools_where VALUES
('1', 'All', 'all', '', '', '1,73,74,78,79,84', '1,2,3,7,8', '1,2,3,4,5,6,7,8,12,13', '1'),
('2', 'Security Policies', 'security_rules', '', '/resources/images/icons/security.gif', '1,2,3,66,5,6,7,8,9,10,11,12,13,14,15,81,82,74,84,86,87,88,89,90,91,92,93,94,95,96,106,107,109,110,112,113,115,116,117,126,127,128,129,132,133,134,135', '1,10,11,3', '1,2,3,4,5,6,7,8,12,13', '2'),
('3', 'Nat Policies', 'nat_rules', '', '/resources/images/icons/nat.gif', '1,2,3,67,68,69,70,71,72,131,15,19,20,21,81,82,74,84,96,109,110,112,115,117,119,120,121,122,123,124,127', '1,10,11,3', '1,2,3,4,5,6,7,8,12,13', '3'),
('4', 'Application Override Policies', 'appoverride_rules', '', '/resources/images/rules/application-override.png', '1,3,15,97,98,99,100,101,102,103,104,82,105,108,84,109,110,112,125', '1,10,11,3', '1,2,3,4,5,6,7,8,12,13','4'),
('5', 'Address', 'address', '', '/resources/images/rules/address.gif', '1,4,15,24,25,85,73,74,75,76,111,78,79,83,114,115,118,84,130,136', '1,2,3,4,5,7,8,12,13', '1,3,4,6,12,13','5'),
('6', 'Address Groups', 'address_groups_id', '', '/resources/images/rules/address_group.gif', '1,4,15,26,73,74,75,76,111,77,78,79,80,114,115,118,84,136', '1,2,3,4,5,6,7,8', '1,3,4,6,9,10,11,12,13', '6'),
('7', 'Services', 'services', '', '/resources/images/rules/service.gif', '1,4,15,23,27,73,74,75,76,111,78,79,114,115,118,84', '1,2,3,4,5,7,8,12,13', '1,3,4,6,12,13', '7'),
('8', 'Services Groups', 'services_groups_id', '', '/resources/images/rules/service_group.gif', '1,4,15,26,73,74,75,76,111,77,78,79,80,114,115,118,84', '1,2,3,4,5,6,7,8', '1,3,4,6,9,10,11,12,13', '8'),
('9', 'Applications', 'applications', '', '/resources/images/rules/application.gif', '1,15,28,29,30,31,32,74,111,78,79,115,118,84', '1,3,4,7,8', '1,3,4,6,12,13', '9'),
('10', 'Applications Filters', 'applications_filters', '', '/resources/images/rules/applications_filters.png', '1,28,29,30,31,32,74,78,79,84,111,118', '1,3,4,7,8', '1,3,4,6,12,13', '10'),
('11', 'Applications Groups', 'applications_groups_id', '', '/resources/images/rules/applications_groups.gif', '1,26,74,75,76,77,78,79,80,84,111,115,118', '1,3,4,6,7,8', '1,3,4,6,9,10,11,12,13', '11'),
('12', 'Default Applications', 'default_applications', '', '/resources/images/rules/application.gif', '1,26,74,75,76,77,78,79,84,111', '1,3,4,6,7,8', '1,3,4,6,9,10,11,12,13', '11.1'),
('13', 'Users', 'userid_group', '', '', '1,74,78,79,84', '1,3,7,8', '1,3,4,6,12,13', '20'),
('14', 'Users Groups', 'userid_group_members', '', '', '1,26,74,80,84', '1,3,9,7,8', '1,3,4,6,12,13', '21'),
('15', 'Regions', 'regions', '', '/resources/images/rules/regions.png', '1,41,42,43,73,74,75,76,78,79,84', '1,2,3,4,5,7,8', '1,3,4,6,12,13', '22'),
('16', 'Tags', 'tag', '', '/resources/images/tags/tags_color3.png', '1,44,74,78,79,84', '1,3,7,8', '1,3,4,6,12,13', '23'),
('18', 'Interfaces', 'interfaces', '', '/resources/images/icons/interfaces.png', '1,49,57,50,51,52,74,84', '1,2,3,7,8', '1,3,4,6,12,13', '27'),
('19', 'Zones', 'zones', '', '/resources/images/rules/zone.gif', '1,49,53,73,74,84', '1,3,7,8', '1,3,4,6,12,13', '28'),
('20', 'Virtual Routers', 'virtual_routers', '', '/resources/images/icons/virtual-routers.png', '1,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '29'),
('21', 'Virtual Wires', 'virtual_wires', '', '/resources/images/icons/virtual-wires.png', '1,54,55,74,84', '1,3,7,8', '1,3,4,6,12,13', '30'),
('22', 'VLANs', 'vlans', '', '/resources/images/icons/vlans.png', '1,53,56,74,84', '1,3,7,8', '1,3,4,6,12,13', '31'),
('23', 'IPSec Tunnels', 'ipsec_tunnel', '', '/resources/images/icons/ipsec-tunnels.png', '1,49,53,73,74,84', '1,3,7,8', '1,3,4,6,12,13', '32'),
('24', 'IKE Crypto', 'ike_crypto_profiles', '', '/resources/images/icons/ipsec-crypto.png', '1,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '33'),
('25', 'IKE Gateways', 'ike_gateways_profiles', '', '/resources/images/icons/ike-gateways.png', '1,54,55,74,84', '1,3,7,8', '1,3,4,6,12,13', '34'),
('26', 'IPSec Crypto', 'ipsec_crypto_profiles', '', '/resources/images/icons/ipsec-crypto.png', '1,53,56,74,84', '1,3,7,8', '1,3,4,6,12,13', '35'),
('27', 'GlobalProtect IPSec Crypto', 'global_protect_app_ipsec_crypto_profiles', '', '/resources/images/icons/ipsec-crypto.png', '1,49,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '36'),
('28', 'Monitor', 'monitor_profile', '', '/resources/images/icons/monitor.png', '1,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '37'),
('29', 'Interface MGMT', 'interface_management_profile', '', '/resources/images/icons/interface-mgmt.png', '1,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '38'),
('30', 'Virtual Systems', 'virtual_systems', '', '/resources/images/icons/device.png', '1,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '39'),
('31', 'Response Pages', 'response_pages', '', '/resources/images/icons/response-pages.png', '1,53,74,84', '1,3,7,8', '1,3,4,6,12,13', '40'),
('33', 'Antivirus', 'profiles', 'virus', '/resources/images/rules/virus.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '12'),
('34', 'Spyware', 'profiles', 'spyware', '/resources/images/rules/spyware.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '13'),
('35', 'Vulnerability', 'profiles', 'vulnerability', '/resources/images/rules/vulnerability.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '14'),
('36', 'Url-Filtering', 'profiles', 'url-filtering', '/resources/images/rules/url_filter.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '15'),
('37', 'File Blocking', 'profiles', 'file-blocking', '/resources/images/rules/fileblocking.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '16'),
('38', 'WildFire', 'profiles', 'wildfire-analysis', '/resources/images/rules/wildfire_analysis.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '17'),
('39', 'Data Filtering', 'profiles', 'data-filtering', '/resources/images/rules/dlp_data_filter.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '18'),
('40', 'Groups', 'profiles_groups', '', '/resources/images/rules/profile_group.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '19'),
('41', 'Log Forward', 'log_settings', 'profiles', '/resources/images/rules/log-forwarding.png', '1,74,84', '1,3', '1,3,4,6,12,13', '24'),
('42', 'External-List', 'external_list', '', '/resources/images/rules/external_list.png', '1,74,84', '1,3', '1,3,4,6,12,13', '25'),
('43', 'Schedules', 'schedules', '', '/resources/images/rules/external_list.png', '1,74,84', '1,3', '1,3,4,6,12,13', '26'),
('44', 'SNMPTrap', 'log_settings', 'snmptrap', '/resources/images/rules/email.png', '1,74,84', '1,3', '1,3,4,6,12,13', '41'),
('45', 'Syslog', 'log_settings', 'syslog', '/resources/images/rules/email.png', '1,74,84', '1,3', '1,3,4,6,12,13', '42'),
('46', 'Email', 'log_settings', 'email', '/resources/images/rules/email.png', '1,74,84', '1,3', '1,3,4,6,12,13', '43'),
('47', 'Netflow', 'server_profile', 'netflow', '/resources/images/rules/email.png', '1,74,84', '1,3', '1,3,4,6,12,13', '44'),
('48', 'RADIUS', 'server_profile', 'radius', '/resources/images/rules/kerberos.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '45'),
('49', 'LDAP', 'server_profile', 'ldap', '/resources/images/rules/kerberos.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '46'),
('50', 'Kerberos', 'server_profile', 'kerberos', '/resources/images/rules/kerberos.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '47'),
('51', 'TACACS+', 'server_profile', 'tacplus', '/resources/images/rules/kerberos.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '48'),
('52', 'DNS', 'server_profile', 'dns', '/resources/images/rules/kerberos.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '49'),
('53', 'Custom Url Category', 'profiles', 'custom-url-category', '/resources/images/rules/url_filter.gif', '1,74,84', '1,3', '1,3,4,6,12,13', '15.1');
/*!40000 ALTER TABLE `tools_where` ENABLE KEYS */;
UNLOCK TABLES;


--
-- Table structure for table `tools_operator`
--

-- DROP TABLE IF EXISTS `tools_operator`;
CREATE TABLE `tools_operator` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(45) NOT NULL,
  `operator` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `tools_operator`
--

LOCK TABLES `tools_operator` WRITE;
/*!40000 ALTER TABLE `tools_operator` DISABLE KEYS */;
INSERT INTO tools_operator
VALUES
('1', 'contains', 'LIKE'),
('2', 'contains.recursive', 'LIKE'),
('3', 'not contains', 'NOT LIKE'),
('4', 'equal', '='),
('5', 'equal.recursive', '='),
('6', 'not equal', '!='),
('7', 'in network', ''),
('8', 'not in network', ''),
('9', 'count.more_than', '>='),
('10', 'count.less_than', '<='),
('11', 'count.equals', '='),
('12', 'starts with', 'LIKE'),
('13', 'ends with', 'LIKE'),
('14', 'last 1 day', '>='),
('15', 'last 1 week', '>='),
('16', 'last 2 weeks', '>='),
('17', 'last 1 month', '>='),
('18', 'last 2 months', '>='),
('19', 'last 6 months', '>='),
('20', 'in source or destination',''),
('21', 'in source',''),
('22', 'in destination','');

/*!40000 ALTER TABLE `tools_operator` ENABLE KEYS */;
UNLOCK TABLES;


--
-- Table structure for table `tools_results`
--

-- DROP TABLE IF EXISTS `tools_results`;
CREATE TABLE `tools_results` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filter_id` int(11) NOT NULL,
  `tools_sql_id` int(11) NOT NULL,
  `member_lid` mediumtext NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `type` varchar(45) NOT NULL,
  `table_name_name` varchar(255) NOT NULL,
  `image` varchar(255) NOT NULL,
  `selected` int(1) NOT NULL DEFAULT '1',
  `source` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



--
-- Table structure for table `ts_agent`
--

-- DROP TABLE IF EXISTS `ts_agent`;
CREATE TABLE `ts_agent` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `unknown_traffic_by_app`
--

-- DROP TABLE IF EXISTS `unknown_traffic_by_app`;
CREATE TABLE `unknown_traffic_by_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `rule_lid` int(11) NOT NULL,
  `app` varchar(255) NOT NULL,
  `dst` varchar(45) NOT NULL,
  `dport` int(11) NOT NULL,
  `proto` varchar(45) NOT NULL,
  `from` varchar(16) NOT NULL,
  `to` varchar(16) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `packets` int(11) NOT NULL,
  `bytes` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`),
  KEY `index2` (`source`),
  KEY `index3` (`vsys`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `user_id_agent`
--

-- DROP TABLE IF EXISTS `user_id_agent`;
CREATE TABLE `user_id_agent` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `xml` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `user_id_collector`
--

-- DROP TABLE IF EXISTS `user_id_collector`;
CREATE TABLE `user_id_collector` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `xml` mediumtext NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `template` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`vsys`,`template`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `virtual_routers`
--

-- DROP TABLE IF EXISTS `virtual_routers`;
CREATE TABLE `virtual_routers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `name_ext` varchar(45),
  `map_name` varchar(31) NOT NULL,
  `interfaces` text NOT NULL,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `admin_dist_static` int(4) NOT NULL DEFAULT '10',
  `admin_dist_ospf_int` int(4) NOT NULL DEFAULT '30',
  `admin_dist_ospf_ext` int(4) NOT NULL DEFAULT '110',
  `admin_dist_ibgp` int(4) NOT NULL DEFAULT '200',
  `admin_dist_ebgp` int(4) NOT NULL DEFAULT '20',
  `admin_dist_rip` int(4) NOT NULL DEFAULT '120',
  `protocol` mediumtext NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `multicast` LONGTEXT NOT NULL DEFAULT '',
  `admin_dist_static_ipv6` int(4) NOT NULL DEFAULT '10',
  `admin_dist_ospfv3_int` int(4) NOT NULL DEFAULT '30',
  `admin_dist_ospfv3_ext` int(4) NOT NULL DEFAULT '110',
  `ecmp` mediumtext NOT NULL,
  `rip_interfaces` text NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `virtual_systems`
--

-- DROP TABLE IF EXISTS `virtual_systems`;
CREATE TABLE `virtual_systems` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `display_name` varchar(31) NOT NULL,
  `interfaces` mediumtext NOT NULL,
  `virtual_router` varchar(1023) NOT NULL,
  `virtual_wire` varchar(1023) NOT NULL,
  `vlan` varchar(1023) NOT NULL,
  `max_application_override_rules` int(11) NOT NULL,
  `max_concurrent_ssl_vpn_tunnels` int(11) NOT NULL,
  `max_cp_rules` int(11) NOT NULL,
  `max_dos_rules` int(11) NOT NULL,
  `max_nat_rules` int(11) NOT NULL,
  `max_pbf_rules` int(11) NOT NULL,
  `max_qos_rules` int(11) NOT NULL,
  `max_security_rules` int(11) NOT NULL,
  `max_sessions` int(11) NOT NULL,
  `max_site_to_site_vpn_tunnels` int(11) NOT NULL,
  `max_ssl_decryption_rules` int(11) NOT NULL,
  `visible_vsys` varchar(1023) NOT NULL,
  `dns_proxy` varchar(31) NOT NULL,
  `allow_forward_decrypted_content` varchar(3) NOT NULL DEFAULT 'no',
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `virtual_wires`
--

-- DROP TABLE IF EXISTS `virtual_wires`;
CREATE TABLE `virtual_wires` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `multicast_firewalling` varchar(3) NOT NULL DEFAULT 'yes',
  `tag_allowed` varchar(255) NOT NULL DEFAULT '0',
  `link_state_pass_through` varchar(3) NOT NULL DEFAULT 'yes',
  `interface1` varchar(45) NOT NULL,
  `interface2` varchar(45) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`id`,`source`,`template`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `vlans`
--

-- DROP TABLE IF EXISTS `vlans`;
CREATE TABLE `vlans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(31) NOT NULL,
  `name_ext` varchar(31),
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  `interface` mediumtext NOT NULL,
  `mac` mediumtext NOT NULL,
  `mac_interfaces` mediumtext NOT NULL,
  `virtual_interface` varchar(45) NOT NULL,
  `l3_forwarding` varchar(3) NOT NULL,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`,`template`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `zone_protection_profile`
--

-- DROP TABLE IF EXISTS `zone_protection_profile`;
CREATE TABLE `zone_protection_profile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vsys` varchar(31) NOT NULL,
  `source` int(11) NOT NULL,
  `template` int(11) NOT NULL,
  `name` varchar(45) NOT NULL,
  `name_ext` varchar(45),
  `xml` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`template`,`name`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `userid_group`
--

-- DROP TABLE IF EXISTS `userid_group`;
CREATE TABLE `userid_group` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `connector` INT(11) NOT NULL,
  `name` TEXT NOT NULL,
  `name_ext` TEXT,
  `short_name` TEXT NOT NULL,
  `type` varchar(45) NOT NULL,
  `origin` varchar(100) NOT NULL,
  `enabled` INT(1) NOT NULL DEFAULT 0,
  `dummy` int(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `userid_group_members`
--

-- DROP TABLE IF EXISTS `userid_group_members`;
CREATE TABLE `userid_group_members` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `connector` INT(11) NOT NULL,
  `lid` INT(11) NOT NULL,
  `name` varchar(1024) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `userid_group_recommended`
--

-- DROP TABLE IF EXISTS `userid_group_recommended`;
CREATE TABLE `userid_group_recommended` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) NOT NULL,
  `img` varchar(20) NOT NULL,
  `rule_lid` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `userid_calculate_recommended`
--

-- DROP TABLE IF EXISTS `userid_calculate_recommended`;
CREATE TABLE `userid_calculate_recommended` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) NOT NULL,
  `lid` varchar(1024) NOT NULL,
  `is_match` INT(2) NOT NULL,
  `lid_is_match` varchar(1024) NOT NULL,
  `is_match_many_groups` INT(2) NOT NULL,
  `lid_is_match_many_groups` varchar(1024) NOT NULL,
  `rule_lid` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `connectors_userid`
--

-- DROP TABLE IF EXISTS `connectors_userid`;
CREATE TABLE `connectors_userid` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  `device` INT(11) NOT NULL,
  `image` varchar(255) NOT NULL,
  `vsys` varchar(31) NOT NULL, 
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `zones`
--

-- DROP TABLE IF EXISTS `zones`;
CREATE TABLE `zones` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` int(11) NOT NULL,
  `template` varchar(31) NOT NULL,
  `vsys` varchar(31) NOT NULL DEFAULT 'vsys1',
  `name` varchar(255) NOT NULL,
  `name_ext` varchar(255) NOT NULL,
  `type` varchar(45) NOT NULL,
  `interfaces` mediumtext NOT NULL,
  `zone_protection_profile` varchar(31) NOT NULL,
  `log_setting_id` int(11) NOT NULL,
  `include_list` mediumtext NOT NULL,
  `exclude_list` mediumtext NOT NULL,
  `enable_user_identification` varchar(3) NOT NULL DEFAULT 'no',
  `log_setting_table_name` varchar(255) NOT NULL,
  `modified` int(1) NOT NULL DEFAULT '1',
  `invalid` int(1) NOT NULL DEFAULT '0',
  `dummy` int(1) DEFAULT '0',
  `enable_packet_buffer_protection` varchar(3) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`source`),
  KEY `index2` (`name`),
  KEY `index3` (`name_ext`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `zones_exclude_list`
--

-- DROP TABLE IF EXISTS `zones_exclude_list`;
CREATE TABLE `zones_exclude_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `zones_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`zones_lid`),
  KEY `index3` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `zones_include_list`
--

-- DROP TABLE IF EXISTS `zones_include_list`;
CREATE TABLE `zones_include_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `zones_lid` int(11) NOT NULL,
  `member_lid` int(11) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index2` (`id`),
  KEY `index1` (`zones_lid`),
  KEY `index3` (`member_lid`,`table_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `userid_from_log`;
CREATE TABLE `userid_from_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) NOT NULL,
  `sessions` bigint(20) NOT NULL,
  `bytes` bigint(20) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` VARCHAR(31) NOT NULL,
  `rule_lid` int(11) NOT NULL,
  `date_retrieve` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `routes_static_monitor_destinations`;
CREATE TABLE `routes_static_monitor_destinations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `route_id` int(11) NOT NULL,
  `name` varchar(31) NOT NULL,
  `enable` varchar(45) NOT NULL DEFAULT 'yes',
  `src` varchar(255) NOT NULL,
  `dst` varchar(255) NOT NULL,
  `dst_member_lid` int(11) NOT NULL,
  `mp_interval` int(11) NOT NULL DEFAULT '3',
  `mp_count` int(11) NOT NULL DEFAULT '5',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `security_rules_target`;
CREATE TABLE `security_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `nat_rules_target`;
CREATE TABLE `nat_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `appoverride_rules_target`;
CREATE TABLE `appoverride_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `pbf_rules_target`;
CREATE TABLE `pbf_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `qos_rules_target`;
CREATE TABLE `qos_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- DROP TABLE IF EXISTS `decryption_rules_target`;
CREATE TABLE `decryption_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `tunnel_inspect_rules_target`;
CREATE TABLE `tunnel_inspect_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `authentication_rules_target`;
CREATE TABLE `authentication_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `dos_rules_target`;
CREATE TABLE `dos_rules_target` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `source` int(11) DEFAULT NULL,
  `vsys` varchar(31) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `device_vsys` varchar(255) DEFAULT NULL,
  `rule_lid` int(11) DEFAULT NULL,
  `xml` text,
  `devicegroup` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`rule_lid`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- DROP TABLE IF EXISTS `PotentialRegions`;
CREATE TABLE `PotentialRegions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `network` varchar(45) DEFAULT NULL,
  `cidr` int(4) DEFAULT NULL,
  `number` float DEFAULT NULL,
  `percentage` float DEFAULT NULL,
  `mode` varchar(45) DEFAULT NULL,
  `name` varchar(45) DEFAULT NULL,
  `enable` varchar(45) DEFAULT NULL,
  `timestamp` datetime DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index1` (`mode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ML_NewRules`(
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source` mediumtext DEFAULT NULL,
  `sourceUser` MEDIUMTEXT NULL,
  `Source_Zone` MEDIUMTEXT NULL,
  `destination` mediumtext DEFAULT NULL,
  `destinationUser` MEDIUMTEXT NULL,
  `Destination_Zone` MEDIUMTEXT NULL,
  `service` mediumtext DEFAULT NULL,
  `application` mediumtext DEFAULT NULL,
  `srcRegion` mediumtext DEFAULT NULL,
  `timestamp` datetime DEFAULT '0000-00-00 00:00:00',
  `rawservice` mediumtext DEFAULT NULL,
  `communicationType` varchar(45) DEFAULT NULL,
  `tag` varchar(45) DEFAULT NULL,
  `seenSourceRegions` MEDIUMTEXT DEFAULT NULL,
  `seenDestinationRegions` MEDIUMTEXT DEFAULT NULL,
  `seenSourceNetworks` MEDIUMTEXT DEFAULT NULL,
  `seenDestinationNetworks` MEDIUMTEXT DEFAULT NULL,
  `minNetworkUsageSource` FLOAT DEFAULT NULL,
  `minNetworkUsageDestination` FLOAT DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ML_Servers` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `serverAddress` VARCHAR(45) NOT NULL,
  `application` VARCHAR(45) NOT NULL,
  `timestamp` datetime DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  KEY `timestamp` (`timestamp`),
  KEY `applicationIndex` (`application`),
  KEY `serverApplication` (`serverAddress`, `application`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ML_ReportedServers` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `serverAddress` VARCHAR(45) NOT NULL,
  `application` VARCHAR(45),
  `container` VARCHAR(45),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `cloud_default_apps`;
CREATE TABLE `cloud_default_apps` (
  `id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(255) CHARACTER SET utf8 NOT NULL,
  `name_ext` varchar(255) CHARACTER SET utf8 DEFAULT NULL,
  `version` varchar(45) CHARACTER SET utf8 NOT NULL,
  `risk` int(11) NOT NULL,
  `category` varchar(150) CHARACTER SET utf8 NOT NULL,
  `subcategory` varchar(150) CHARACTER SET utf8 NOT NULL,
  `technology` varchar(150) CHARACTER SET utf8 NOT NULL,
  `evasive_behavior` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `consume_big_bandwidth` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `used_by_malware` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `able_to_transfer_file` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `has_known_vulnerability` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `tunnel_other_application` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `prone_to_misuse` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `pervasive_use` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `default_port` varchar(355) CHARACTER SET utf8 NOT NULL,
  `default_protocol` int(11) NOT NULL,
  `dependency` mediumtext CHARACTER SET utf8 NOT NULL,
  `functions` mediumtext CHARACTER SET utf8 NOT NULL,
  `implicit` mediumtext CHARACTER SET utf8 NOT NULL,
  `container` varchar(250) CHARACTER SET utf8 NOT NULL,
  `dummy` int(1) DEFAULT '0',
  `issaas` varchar(3) CHARACTER SET utf8 DEFAULT 'no',
  `ori_country` varchar(255) CHARACTER SET utf8 DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cloud_default_apps`
--
LOCK TABLES `cloud_default_apps` WRITE;
/*!40000 ALTER TABLE `cloud_default_apps` DISABLE KEYS */;
INSERT INTO `cloud_default_apps` VALUES (1,'100bao',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/3468,6346,11300',0,'','','','',0,'no','USA'),(11,'1und1-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','Germany'),(12,'24sevenoffice',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(13,'2ch-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','2ch',0,'no','USA'),(14,'2ch-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'2ch-base,web-browsing','','','2ch',0,'no','USA'),(17,'4shared',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(18,'4sync',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','no','no','no','yes','tcp/80,443',0,'flash,google-analytics,ocsp,ssl,web-browsing','','','',0,'yes','USA'),(19,'51.com-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,dynamic',0,'web-browsing','','','51.com',0,'no','China'),(20,'51.com-bbs',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'51.com-base,web-browsing','','','51.com',0,'no','China'),(21,'51.com-games',NULL,'',2,'media','gaming','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'51.com-base,web-browsing','','','51.com',0,'no','China'),(22,'51.com-mail',NULL,'',1,'collaboration','email','browser-based','no','no','no','no','yes','no','no','no','tcp/80',0,'51.com-base,web-browsing','','','51.com',0,'yes','China'),(23,'51.com-music',NULL,'',2,'media','audio-streaming','browser-based','no','yes','no','no','yes','no','no','yes','tcp/80',0,'51.com-base,web-browsing','','','51.com',0,'no','China'),(24,'51.com-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'51.com-base,web-browsing','','','51.com',0,'no','China'),(25,'51.com-webdisk',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80',0,'51.com-base,web-browsing','','','51.com',0,'no','China'),(26,'7shifts',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(31,'accellion',NULL,'',4,'general-internet','file-sharing','client-server','no','no','yes','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','USA'),(32,'accelo',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(40,'adobe-cloud',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(41,'adobe-meeting',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','no','no','no','yes','yes','no','no','tcp/80,443,1935',0,'flash,rtmp,rtmpt,ssl,web-browsing','','','adobe-connect',0,'yes','USA'),(42,'adobe-meeting-remote-control',NULL,'',3,'networking','remote-access','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/443,80,1935',0,'adobe-meeting,ssl,web-browsing,flash,rtmp,rtmpt','','','adobe-connect',0,'yes','USA'),(43,'adobe-connectnow-base',NULL,'',2,'collaboration','internet-conferencing','browser-based','no','yes','no','no','yes','no','no','yes','tcp/80,443,1935',0,'flash,rtmp,rtmpt,ssl,web-browsing','','','adobe-connectnow',0,'yes','USA'),(44,'adobe-connectnow-file-transfer',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/443',0,'adobe-connectnow-base,ssl,web-browsing,flash,rtmp,rtmpt','','','adobe-connectnow',0,'yes','USA'),(45,'adobe-connectnow-remote-control',NULL,'',1,'networking','remote-access','browser-based','no','no','no','no','no','no','no','yes','tcp/1935',0,'adobe-connectnow-base,rtmp,flash,rtmpt,ssl,web-browsing','','','adobe-connectnow',0,'yes','USA'),(47,'adobe-creative-cloud-base',NULL,'',2,'business-systems','general-business','client-server','no','no','no','yes','yes','no','no','no','tcp/443',0,'flash,ssl,web-browsing','','','adobe-creative-cloud',0,'yes','USA'),(48,'adobe-creative-cloud-uploading',NULL,'',3,'business-systems','general-business','client-server','no','no','no','yes','yes','no','yes','yes','tcp/443',0,'adobe-creative-cloud-base,ssl,web-browsing,flash','','','adobe-creative-cloud',0,'yes','USA'),(49,'adobe-echosign',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(52,'adobe-meeting-desktop-sharing',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','yes','no','no','yes','no','no','yes','tcp/443,80,1935',0,'adobe-meeting,ssl,web-browsing,flash,rtmp,rtmpt','','','adobe-connect',0,'yes',''),(53,'adobe-meeting-file-transfer',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/443,80,1935',0,'ssl,web-browsing','','','adobe-connect',0,'yes','USA'),(54,'adobe-meeting-uploading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443,1935',0,'ssl,web-browsing','','','adobe-connect',0,'yes',''),(55,'adobe-online-office',NULL,'',3,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'flash,ssl,web-browsing','','','',0,'yes','USA'),(56,'adobe-update',NULL,'',2,'business-systems','software-update','client-server','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'','','web-browsing','',0,'no','USA'),(57,'adrive',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'yes','USA'),(58,'aerofs',NULL,'',3,'general-internet','file-sharing','client-server','no','yes','no','yes','yes','no','no','no','tcp/80,443,4433,5222,8888,29438,8084,3478',0,'ssl,web-browsing','','','',0,'yes','USA'),(64,'agiloft',NULL,'',2,'business-systems','general-business','client-server','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes',''),(65,'aim-base',NULL,'',4,'collaboration','instant-messaging','client-server','no','no','yes','no','yes','yes','no','yes','tcp/80,443,5190-5199',0,'ssl,web-browsing','','','aim',0,'no','USA'),(66,'aim-audio',NULL,'',5,'collaboration','voip-video','peer-to-peer','yes','no','yes','yes','yes','no','no','yes','udp/dynamic',0,'sip','','','aim',0,'no','USA'),(67,'aim-express-base',NULL,'',4,'collaboration','instant-messaging','browser-based','yes','no','yes','no','yes','yes','no','yes','tcp/443,tcp/80',0,'aim-base,ssl,web-browsing','','','aim-express',0,'no','USA'),(68,'aim-express-file-transfer',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','aim-express',0,'yes','USA'),(69,'aim-file-transfer',NULL,'',4,'general-internet','file-sharing','peer-to-peer','no','no','yes','yes','yes','no','no','yes','tcp/80,443,5190-5199',0,'ssl,web-browsing','','','aim',0,'no','USA'),(70,'aim-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443,110,25,587,143,993',0,'imap,pop3,smtp,ssl,web-browsing','','','',0,'yes','USA'),(71,'aim-video',NULL,'',3,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','no','no','yes','tcp/1935,udp/dynamic',0,'aim-base,aim-audio,rtmp,ssl,web-browsing,sip','','','aim',0,'no','USA'),(75,'airtime',NULL,'',2,'collaboration','voip-video','browser-based','no','yes','no','no','yes','no','no','no','tcp/dynamic,udp/dynamic',0,'facebook-base,flash,google-maps,rtmfp,rtmp,ssl,web-browsing,google-base','','','',0,'yes','USA'),(77,'alfresco',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(78,'ali-wangwang-base',NULL,'',3,'collaboration','instant-messaging','client-server','yes','no','no','no','yes','no','no','yes','tcp/80,dynamic,udp/dynamic',0,'alisoft,web-browsing','','','ali-wangwang',0,'no','China'),(79,'ali-wangwang-audio-video',NULL,'',2,'collaboration','voip-video','client-server','yes','yes','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'ali-wangwang-base,alisoft,web-browsing','','','ali-wangwang',0,'yes','USA'),(80,'ali-wangwang-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','yes','yes','no','yes','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'ali-wangwang-base,alisoft,web-browsing','','','ali-wangwang',0,'yes','China'),(81,'ali-wangwang-remote-control',NULL,'',2,'networking','remote-access','client-server','yes','no','no','no','no','no','yes','yes','tcp/443,dynamic,udp/dynamic',0,'ali-wangwang-base,alisoft,web-browsing','','','ali-wangwang',0,'no','China'),(82,'alisoft',NULL,'',3,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(84,'allpeers',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/443',0,'ssl','','','',0,'no','USA'),(88,'amazon-aws-console',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','no','no','no','yes','tcp/443,80',0,'ssl,web-browsing','','','',0,'no','USA'),(89,'amazon-cloud-drive-base',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','amazon-cloud-drive',0,'yes','USA'),(90,'amazon-cloud-drive-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/80,443',0,'amazon-cloud-drive-base,ssl,web-browsing','','','amazon-cloud-drive',0,'yes','USA'),(91,'amazon-cloud-player',NULL,'',3,'media','audio-streaming','browser-based','no','yes','no','yes','yes','no','no','no','tcp/443,80',0,'amazon-cloud-drive-uploading,flash,ssl,web-browsing,amazon-cloud-drive-base','','','',0,'no','USA'),(92,'amazon-instant-video',NULL,'',3,'media','photo-video','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/80,443',0,'ocsp,rtmpe,ssl,web-browsing','','','',0,'no','USA'),(93,'amazon-redshift',NULL,'',1,'business-systems','database','client-server','no','no','no','no','yes','no','no','no','tcp/5439',0,'postgres','','','',0,'no',''),(94,'amazon-unbox',NULL,'',4,'media','photo-video','client-server','yes','yes','no','yes','yes','no','no','yes','tcp/80',0,'rss,ssl,web-browsing','','','',0,'no','USA'),(95,'amazon-workspace',NULL,'',2,'business-systems','software-development','client-server','no','yes','no','no','yes','no','no','no','tcp/443,4172',0,'pcoip,ssl','','','',0,'no',''),(97,'ameba-now-base',NULL,'',4,'collaboration','social-networking','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','ameba-now',0,'no','Japan'),(98,'ameba-now-posting',NULL,'',4,'collaboration','social-networking','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','ameba-now',0,'no','Japan'),(99,'ammyy-admin',NULL,'',3,'networking','remote-access','client-server','yes','no','no','yes','no','yes','no','no','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(102,'ants-p2p',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/443,80,6667,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(112,'appcelerator',NULL,'',4,'business-systems','software-development','client-server','no','no','yes','yes','yes','no','no','no','tcp/443',0,'google-analytics,ssl,websocket','','web-browsing','',0,'yes',''),(113,'appdynamics',NULL,'',1,'business-systems','erp-crm','client-server','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(115,'apple-airplay',NULL,'',1,'media','photo-video','client-server','no','yes','no','no','no','no','no','yes','tcp/80,5000,7100,udp/7010,7011',0,'rtcp,rtp-base','','rtsp,web-browsing','',0,'no','USA'),(116,'apple-airport',NULL,'',2,'networking','infrastructure','network-protocol','no','no','no','no','yes','no','no','yes','udp/192',0,'','','','',0,'no','USA'),(117,'apple-appstore',NULL,'',4,'general-internet','internet-utility','client-server','yes','no','no','yes','yes','no','no','yes','tcp/80,443,dynamic',0,'itunes-base,ssl,web-browsing','','','',0,'no','USA'),(118,'apple-game-center',NULL,'',1,'media','gaming','client-server','no','no','no','no','yes','no','no','no','tcp/443',0,'apple-appstore,itunes-base,rtp-base,ssl,web-browsing','','','',0,'no','USA'),(119,'apple-location-service',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','yes','yes','tcp/80',0,'web-browsing','','','',0,'no','USA'),(120,'apple-maps',NULL,'',1,'general-internet','internet-utility','client-server','no','yes','no','no','no','no','no','yes','tcp/80,443',0,'web-browsing','','ssl','',0,'no','USA'),(121,'apple-push-notifications',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','no','no','no','yes','tcp/2195,2196,5223,443',0,'','','ssl,web-browsing','',0,'no','USA'),(122,'apple-remote-desktop',NULL,'',3,'networking','remote-access','client-server','no','no','no','yes','yes','yes','no','yes','tcp/5900,3283,udp/3283',0,'vnc-base,vnc-encrypted','','','',0,'no','USA'),(123,'apple-siri',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','yes','no','no','no','tcp/443',0,'','','ssl,web-browsing','',0,'no',''),(124,'apple-update',NULL,'',3,'business-systems','software-update','client-server','yes','yes','no','yes','no','no','no','yes','tcp/80,443',0,'apple-appstore,itunes-base,ssl,web-browsing','','web-browsing','',0,'no','USA'),(125,'apple-vpp',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','no','no','no','yes','tcp/443',0,'ssl,web-browsing','','','',0,'no','USA'),(126,'applejuice',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','udp/9022,9851,tcp/9022,9851',0,'web-browsing','','','',0,'no','USA'),(127,'appogee',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'google-base,ssl,web-browsing','','','',0,'yes',''),(128,'appointy',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'google-base,ssl,web-browsing','','','',0,'yes',''),(129,'apptivo',NULL,'',1,'business-systems','erp-crm','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'google-analytics,google-base,ssl,web-browsing','','','',0,'yes',''),(133,'ares',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','yes','yes','yes','tcp/dynamic,udp/dynamic',0,'emule,web-browsing','','','',0,'no','USA'),(139,'asana',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'ssl','','web-browsing','',0,'yes','USA'),(143,'asterisk-iax',NULL,'',2,'collaboration','voip-video','peer-to-peer','no','no','no','no','yes','no','no','yes','udp/4569',0,'','','','',0,'no','USA'),(144,'asus-webstorage',NULL,'',3,'general-internet','file-sharing','client-server','yes','yes','no','yes','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','Taiwan'),(146,'atlassian-bamboo-cloud',NULL,'',2,'business-systems','software-development','browser-based','no','no','no','no','yes','no','no','yes','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(149,'att-connect',NULL,'',4,'collaboration','internet-conferencing','client-server','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(150,'att-locker',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','no','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(151,'att-office-at-hand',NULL,'',1,'collaboration','voip-video','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ringcentral,ssl,sip,web-browsing','','','',0,'yes','USA'),(154,'autodesk360-base',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','no','yes','no','yes','tcp/443',0,'ssl','','','autodesk360',0,'yes','USA'),(155,'autodesk360-uploading',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','no','no','yes','no','tcp/443',0,'autodesk360-base,ssl,web-browsing','','','autodesk360',0,'yes','USA'),(157,'avast-av-update',NULL,'',1,'business-systems','software-update','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'no','USA'),(159,'avaya-webalive-base',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','no','no','no','yes','no','no','no','tcp/dynamic,udp/7878,2379',0,'ssl,web-browsing','','','avaya-webalive',0,'yes','USA'),(160,'avaya-webalive-desktop-sharing',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','yes','no','no','yes','no','yes','no','tcp/80,1935',0,'avaya-webalive-base,rtmp,ssl,web-browsing','','','avaya-webalive',0,'yes','USA'),(161,'avaya-webalive-file-transfer',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','yes','no','tcp/80',0,'avaya-webalive-base,ssl,web-browsing','','','avaya-webalive',0,'yes','USA'),(162,'avaya-webalive-voice',NULL,'',1,'collaboration','voip-video','browser-based','no','yes','no','no','no','no','no','no','udp/2379',0,'avaya-webalive-base,ssl,web-browsing','','','avaya-webalive',0,'yes','USA'),(163,'avg-update',NULL,'',1,'business-systems','software-update','client-server','no','no','no','no','no','no','no','yes','tcp/80',0,'','','web-browsing','',0,'no','Czech Republic Czech Republic '),(170,'axifile',NULL,'',5,'general-internet','file-sharing','browser-based','yes','no','yes','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(171,'azureus',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'bittorrent,web-browsing','','','',0,'no','USA'),(172,'babelgum',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','no','yes','no','yes','yes','tcp/80',0,'web-browsing','','','',0,'no','USA'),(174,'backblaze-backup',NULL,'',3,'business-systems','storage-backup','client-server','no','no','no','yes','yes','no','yes','yes','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(177,'backweb',NULL,'',1,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','no','no','udp/370,377',0,'','','','',0,'yes','USA'),(182,'baidu-hi-base',NULL,'',3,'collaboration','instant-messaging','client-server','no','no','yes','no','yes','no','no','yes','tcp/443,80,6453,dynamic,udp/2400,2500,dynamic',0,'ssl,web-browsing','','','baidu-hi',0,'no','China'),(183,'baidu-hi-audio-video',NULL,'',2,'collaboration','voip-video','client-server','no','no','no','no','yes','no','no','yes','udp/dynamic',0,'baidu-hi-base,ssl,web-browsing','','','baidu-hi',0,'yes','China'),(184,'baidu-hi-file-transfer',NULL,'',4,'general-internet','file-sharing','client-server','no','no','yes','yes','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'baidu-hi-base,ssl,web-browsing','','','baidu-hi',0,'no','China'),(185,'baidu-hi-games',NULL,'',3,'media','gaming','client-server','yes','no','no','no','yes','no','no','yes','tcp/80,dynamic',0,'baidu-hi-base,web-browsing,ssl','','','baidu-hi',0,'no','China'),(188,'baofeng',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'http-video,web-browsing','','','',0,'no','USA'),(189,'barracuda-backup',NULL,'',2,'business-systems','storage-backup','client-server','no','yes','no','yes','no','no','no','no','tcp/80,443,5120-5129,8000',0,'open-vpn,ssl,web-browsing','','ssl,web-browsing','',0,'yes','USA'),(190,'base-crm',NULL,'',4,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','yes','yes','no','tcp/80,443',0,'amazon-cloud-drive-base,amazon-cloud-drive-uploading,new-relic,ssl,twilio,web-browsing,rtcp,rtp-base,stun,websocket','','','',0,'yes','USA'),(191,'batchbook',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(197,'beampro-telepresence',NULL,'',1,'business-systems','general-business','peer-to-peer','no','yes','no','no','no','no','no','no','udp/6868,6871',0,'','','','',0,'no',''),(198,'beamyourscreen',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','yes','no','no','no','tcp/443,80',0,'mikogo,ssl,web-browsing','','','',0,'yes','Germany'),(200,'bebo-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/80,443',0,'web-browsing','','','bebo',0,'no','USA'),(201,'bebo-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','bebo',0,'no','USA'),(202,'bebo-posting',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','bebo',0,'no','USA'),(204,'benchmark',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(211,'bime',NULL,'',2,'business-systems','general-business','client-server','no','no','no','yes','yes','no','no','no','tcp/443,tcp/80',0,'ssl','','web-browsing','',0,'yes',''),(212,'bing-maps',NULL,'',1,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'no',''),(214,'bitbucket-base',NULL,'',3,'business-systems','management','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/443',0,'ssl,web-browsing','','','bitbucket',0,'yes','USA'),(215,'bitbucket-uploading',NULL,'',3,'business-systems','management','client-server','no','no','no','yes','yes','no','no','yes','tcp/443',0,'bitbucket-base,ssl,web-browsing','','','bitbucket',0,'yes','USA'),(216,'bitcasa',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes','USA'),(217,'bitcoin',NULL,'',4,'general-internet','internet-utility','peer-to-peer','no','yes','yes','no','yes','no','yes','yes','tcp/3333,8332,8333,18333',0,'stratum-mining-protocol','','web-browsing','',0,'no','USA'),(219,'bitrix24',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(220,'bittorrent',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','yes','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(222,'bkper',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'google-analytics,google-base,ssl,web-browsing','','','',0,'yes',''),(224,'blackboard',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','yes','no','no','no','no','tcp/dynamic',0,'elluminate,ssl,web-browsing','','','',0,'yes','USA'),(225,'blin',NULL,'',3,'media','photo-video','peer-to-peer','yes','yes','no','no','no','no','yes','yes','udp/dynamic',0,'','','','',0,'no','USA'),(232,'bluejeans',NULL,'',2,'collaboration','internet-conferencing','browser-based','no','yes','no','no','yes','no','no','no','tcp/80,443,5061,udp/dynamic',0,'rtcp,rtp-base,ssl,stun,web-browsing','','','',0,'yes','USA'),(237,'bomgar',NULL,'',4,'networking','remote-access','client-server','yes','no','no','yes','yes','yes','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(240,'boxnet-base',NULL,'',3,'general-internet','file-sharing','browser-based','yes','yes','no','yes','no','no','yes','no','tcp/80,443',0,'ssl,web-browsing','','','boxnet',0,'yes','USA'),(241,'boxnet-consumer-access',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','no','yes','yes','yes','yes','tcp/443',0,'boxnet-base,ssl,web-browsing','','','boxnet',0,'yes','USA'),(242,'boxnet-downloading',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443',0,'boxnet-base,ssl,web-browsing','','','boxnet',0,'yes',''),(243,'boxnet-editing',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'boxnet-base,ssl,web-browsing','','','boxnet',0,'yes','USA'),(244,'boxnet-enterprise-access',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','no','yes','yes','yes','yes','tcp/443',0,'boxnet-base,ssl,web-browsing','','','boxnet',0,'yes','USA'),(245,'boxnet-sharing',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','no','yes','no','no','yes','tcp/443',0,'boxnet-base,ssl,web-browsing','','','boxnet',0,'yes',''),(246,'boxnet-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'boxnet-base,ssl,web-browsing','','','boxnet',0,'yes','USA'),(254,'buddybuddy-base',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','no','no','no','yes','tcp/dynamic',0,'','','','buddybuddy',0,'no','Korea'),(255,'buddybuddy-file-transfer',NULL,'',2,'general-internet','file-sharing','client-server','no','yes','no','yes','no','no','no','yes','tcp/dynamic',0,'','','','buddybuddy',0,'no','Korea'),(257,'buzzsaw',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','yes','no','tcp/80,443',0,'ssl,web-browsing,webdav','','','',0,'yes','USA'),(264,'cakehr',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(267,'callidus',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','no','yes','no','no','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes','USA'),(268,'callpilot',NULL,'',1,'collaboration','email','browser-based','no','no','no','no','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(269,'camfrog',NULL,'',5,'collaboration','voip-video','peer-to-peer','yes','yes','yes','yes','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'yes','USA'),(272,'campfire',NULL,'',3,'collaboration','internet-conferencing','browser-based','no','no','yes','yes','no','no','yes','no','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(274,'canvas',NULL,'',4,'business-systems','general-business','browser-based','no','no','yes','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(276,'carbonite',NULL,'',3,'business-systems','storage-backup','browser-based','yes','yes','no','yes','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(282,'celoxis',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(283,'centriccrm',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','no','yes','tcp/80',0,'','','','',0,'yes','USA'),(286,'certify',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(302,'chinaren-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'ssl,web-browsing','','','chinaren',0,'no','China'),(303,'chinaren-apps',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'chinaren-base,web-browsing,ssl','','','chinaren',0,'no','China'),(304,'chinaren-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80',0,'chinaren-base,web-browsing,ssl','','','chinaren',0,'no','China'),(305,'chinaren-mail',NULL,'',2,'collaboration','email','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'chinaren-base,web-browsing,ssl','','','chinaren',0,'yes','China'),(306,'chinaren-posting',NULL,'',3,'collaboration','web-posting','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'chinaren-base,web-browsing,ssl','','','chinaren',0,'no','China'),(314,'cisco-spark-base',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing,webex-base,websocket','','','cisco-spark',0,'no',''),(315,'cisco-spark-audio-video',NULL,'',2,'collaboration','voip-video','peer-to-peer','no','yes','no','no','yes','no','no','no','tcp/5004,33434,udp/5004,33434',0,'stun','','','cisco-spark',0,'no',''),(316,'cisco-spark-file-transfer',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'cisco-spark-base,jungledisk,ssl,web-browsing,webex-base,websocket','','','cisco-spark',0,'no',''),(325,'clarizen',NULL,'',3,'business-systems','management','browser-based','yes','no','no','yes','no','no','yes','yes','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(327,'clearslide',NULL,'',3,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','yes','no','tcp/80,443',0,'web-browsing','','ssl','',0,'yes','USA'),(329,'clicktools',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes',''),(332,'cloud9',NULL,'',3,'business-systems','management','browser-based','no','no','no','yes','yes','no','yes','yes','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(333,'cloudapp-base',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','cloudapp',0,'yes',''),(334,'cloudapp-uploading',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'cloudapp-base,ssl,web-browsing','','','cloudapp',0,'yes',''),(335,'cloudcherry',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(337,'cloudon',NULL,'',2,'business-systems','office-programs','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443,udp/dynamic',0,'rtp-base','','ssl,web-browsing','',0,'yes','USA'),(338,'cloudshare',NULL,'',4,'business-systems','software-development','browser-based','no','no','yes','yes','yes','no','no','no','tcp/443,80',0,'ftp,ssl,web-browsing,websocket,zendesk','','','',0,'yes',''),(339,'cloudsigma',NULL,'',1,'networking','infrastructure','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(345,'comcast-webmail',NULL,'',3,'collaboration','email','browser-based','no','no','yes','yes','no','no','no','yes','tcp/80,443',0,'web-browsing,zimbra','','','',0,'yes','USA'),(349,'computrace',NULL,'',3,'business-systems','general-business','client-server','yes','no','no','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(350,'concur-base',NULL,'',4,'business-systems','general-business','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','concur',0,'yes','USA'),(351,'concur-downloading',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'concur-base,ssl,web-browsing','','','concur',0,'yes',''),(352,'concur-editing',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'concur-base,ssl,web-browsing','','','concur',0,'yes',''),(353,'concur-uploading',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'concur-base,ssl,web-browsing','','','concur',0,'yes',''),(355,'confluence-base',NULL,'',3,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','confluence',0,'yes','USA'),(356,'confluence-downloading',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'confluence-base,ssl,web-browsing','','','confluence',0,'yes',''),(357,'confluence-editing',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'confluence-base,ssl,web-browsing','','','confluence',0,'yes',''),(358,'confluence-posting',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'confluence-base,ssl,web-browsing','','','confluence',0,'yes',''),(359,'confluence-sharing',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'confluence-base,ssl,web-browsing','','','confluence',0,'yes',''),(360,'confluence-uploading',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'confluence-base,ssl,web-browsing','','','confluence',0,'yes',''),(361,'constant-contact',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(362,'convo-base',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'jabber,ssl,web-browsing','','','convo',0,'yes','USA'),(363,'convo-chat',NULL,'',1,'collaboration','instant-messaging','browser-based','no','no','no','no','no','no','no','no','tcp/80,443',0,'convo-base,jabber,ssl,web-browsing','','','convo',0,'yes','USA'),(364,'convo-uploading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'amazon-cloud-drive-uploading,convo-base,ssl,web-browsing,amazon-cloud-drive-base,jabber','','','convo',0,'yes','USA'),(372,'cox-webmail',NULL,'',3,'collaboration','email','browser-based','no','no','yes','yes','no','no','no','yes','tcp/80, 443',0,'web-browsing','','','',0,'yes','USA'),(377,'crashplan',NULL,'',4,'business-systems','storage-backup','client-server','yes','yes','no','yes','yes','no','no','no','tcp/443,4282',0,'','','','',0,'yes','USA'),(382,'cubby',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','no','no','no','yes','tcp/80,443,udp/dynamic',0,'logmein,adobe-flash-socketpolicy-server','','ssl,web-browsing','',0,'yes','USA'),(400,'dapulse',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(401,'data-bin',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes','USA'),(402,'datadog',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(403,'datto-backupify',NULL,'',4,'business-systems','storage-backup','browser-based','no','no','yes','yes','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing,zendesk','','','',0,'yes',''),(404,'daum-blog-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'ssl,web-browsing','','','daum',0,'no','Korea'),(405,'daum-cafe-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'ssl,web-browsing','','','daum',0,'no','Korea'),(406,'daum-cloud',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','daum',0,'yes','Korea'),(407,'daum-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,4280',0,'ssl,web-browsing','','','daum',0,'yes','Korea'),(414,'huawei-dbank',NULL,'',3,'general-internet','internet-utility','client-server','no','no','no','yes','yes','no','yes','yes','tcp/80,443',0,'web-browsing','','ssl','',0,'yes','USA'),(415,'direct-connect',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','yes','yes','yes','tcp/any',0,'web-browsing','','','',0,'no','USA'),(419,'dcinside-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','yes','no','yes','no','no','yes','tcp/80,443,8080',0,'ssl,web-browsing','','','dcinside',0,'no','Korea'),(420,'dcinside-posting',NULL,'',3,'collaboration','web-posting','browser-based','no','no','yes','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','dcinside',0,'no','Korea'),(431,'depositfiles',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','no','no','yes','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(433,'desknets',NULL,'',1,'networking','remote-access','client-server','no','yes','no','no','no','no','no','no','tcp/52300',0,'web-browsing','','','',0,'yes','USA'),(434,'deskshare',NULL,'',3,'networking','remote-access','browser-based','yes','yes','no','no','yes','no','yes','no','tcp/80',0,'web-browsing','','','',0,'yes','Germany'),(441,'dialpad',NULL,'',4,'collaboration','voip-video','client-server','no','yes','yes','yes','yes','no','no','no','tcp/80,443,7060,udp/7060',0,'google-app-engine,sip,ssl,web-browsing,google-base','','','',0,'yes',''),(446,'diino',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','yes','no','tcp/80, 443',0,'ssl,web-browsing','','','',0,'yes','USA'),(454,'divshare',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/443,tcp/80',0,'web-browsing','','','',0,'yes','USA'),(465,'dochub-base',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'google-analytics','','ssl,web-browsing','dochub',0,'yes','USA'),(466,'dochub-uploading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'dochub-base,google-analytics','','ssl,web-browsing','dochub',0,'yes','USA'),(467,'docstoc-base',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl','','web-browsing','docstoc',0,'yes','USA'),(468,'docstoc-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'docstoc-base,ssl,web-browsing','','','docstoc',0,'yes','USA'),(469,'docusign',NULL,'',3,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes','USA'),(479,'drivehq',NULL,'',4,'business-systems','storage-backup','client-server','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(483,'dropbox-base',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','no','yes','tcp/17500,tcp/443,tcp/80,udp/17500',0,'web-browsing','','ssl','dropbox',0,'yes','USA'),(484,'dropbox-downloading',NULL,'',2,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'dropbox-base,ssl,web-browsing','','web-browsing','dropbox',0,'yes',''),(485,'dropbox-editing',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'dropbox-base,ssl,web-browsing','','web-browsing','dropbox',0,'yes',''),(486,'dropbox-paper',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'dropbox-base,ssl,web-browsing','','','dropbox',0,'yes',''),(487,'dropbox-posting',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'dropbox-base,ssl,web-browsing','','web-browsing','dropbox',0,'yes',''),(488,'dropbox-sharing',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'dropbox-base,ssl,web-browsing','','web-browsing','dropbox',0,'yes',''),(489,'dropbox-uploading',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'dropbox-base,ssl,web-browsing','','web-browsing','dropbox',0,'yes',''),(491,'droplr',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(492,'dropsend',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','USA'),(493,'druva-insync',NULL,'',3,'business-systems','storage-backup','client-server','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl','','','',0,'yes',''),(494,'druva-phoenix',NULL,'',3,'business-systems','storage-backup','client-server','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl','','','',0,'yes',''),(500,'e-signlive',NULL,'',4,'business-systems','office-programs','browser-based','no','no','yes','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(508,'ecount-erp',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443,8462,8472',0,'silverlight,ssl,web-browsing,websocket','','','',0,'yes',''),(510,'efolder',NULL,'',3,'business-systems','storage-backup','client-server','no','yes','no','yes','no','no','yes','yes','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','USA'),(513,'egnyte-base',NULL,'',4,'business-systems','storage-backup','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','egnyte',0,'yes','USA'),(514,'egnyte-downloading',NULL,'',2,'business-systems','storage-backup','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'egnyte-base','','','egnyte',0,'yes',''),(515,'egnyte-editing',NULL,'',1,'business-systems','storage-backup','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'egnyte-base','','','egnyte',0,'yes',''),(516,'egnyte-posting',NULL,'',1,'business-systems','storage-backup','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'egnyte-base,egnyte-downloading','','','egnyte',0,'yes',''),(517,'egnyte-sharing',NULL,'',1,'business-systems','storage-backup','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'egnyte-base','','','egnyte',0,'yes',''),(518,'egnyte-uploading',NULL,'',2,'business-systems','storage-backup','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'egnyte-base','','','egnyte',0,'yes',''),(526,'elluminate',NULL,'',4,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','no','yes','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(535,'emule',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'','','','',0,'no','USA'),(538,'engineyard',NULL,'',1,'business-systems','software-development','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(544,'eroom-net',NULL,'',4,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/443,80',0,'soap,ssl,web-browsing','','','',0,'yes','USA'),(546,'eset-update',NULL,'',1,'business-systems','software-update','client-server','no','no','no','no','yes','no','no','no','tcp/80,2221',0,'','','web-browsing','',0,'no','USA'),(555,'eventbrite',NULL,'',4,'business-systems','general-business','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'yes',''),(556,'evercontact',NULL,'',1,'collaboration','email','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(557,'evernote-base',NULL,'',2,'business-systems','office-programs','client-server','yes','no','no','no','no','yes','no','yes','tcp/443,tcp/80',0,'','','ssl,web-browsing','evernote',0,'yes','USA'),(558,'evernote-downloading',NULL,'',2,'business-systems','office-programs','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'evernote-base,ssl,web-browsing','','','evernote',0,'yes',''),(559,'evernote-editing',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'evernote-base,ssl,web-browsing','','','evernote',0,'yes',''),(560,'evernote-posting',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'evernote-base,ssl,web-browsing','','','evernote',0,'yes',''),(561,'evernote-sharing',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'evernote-base,ssl,web-browsing','','','evernote',0,'yes',''),(562,'evernote-uploading',NULL,'',2,'business-systems','office-programs','client-server','no','no','no','yes','no','no','yes','yes','tcp/80,443',0,'evernote-base,ssl,web-browsing','','','evernote',0,'yes','USA'),(566,'eyejot',NULL,'',2,'collaboration','voip-video','browser-based','no','yes','no','yes','no','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(570,'facebook-base',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','yes','no','yes','tcp/80,443',0,'','','ssl,web-browsing','facebook',0,'no','USA'),(571,'facebook-apps',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','no','yes','yes','no','yes','tcp/80,443',0,'facebook-base','','web-browsing','facebook',0,'no','USA'),(572,'facebook-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','yes','no','yes','tcp/80,443',0,'facebook-base,mqtt','','jabber,web-browsing','facebook',0,'no','USA'),(573,'facebook-code',NULL,'',1,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'facebook-base','','ssl,web-browsing','facebook',0,'no',''),(574,'facebook-file-sharing',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'facebook-base,facebook-chat,mqtt','','web-browsing','facebook',0,'yes','USA'),(575,'facebook-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'facebook-base','','web-browsing','facebook',0,'yes','USA'),(576,'facebook-posting',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/443,80',0,'facebook-base,facebook-apps,facebook-chat,mqtt','','web-browsing','facebook',0,'no','USA'),(577,'facebook-rooms',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','no','no','yes','yes','tcp/80,443',0,'facebook-base,ssl,web-browsing','','','facebook',0,'no','USA'),(578,'facebook-social-plugin',NULL,'',3,'collaboration','social-networking','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'facebook-base','','web-browsing','facebook',0,'no','USA'),(579,'facebook-video',NULL,'',4,'media','photo-video','browser-based','no','yes','no','yes','yes','no','yes','yes','tcp/443',0,'facebook-base,web-browsing','','ssl','facebook',0,'no','USA'),(580,'facebook-voice',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','no','no','no','no','no','no','yes','tcp/443',0,'facebook-chat,mqtt,rtcp,rtp-base,ssl,stun,facebook-base','','','facebook',0,'no','USA'),(581,'facetime',NULL,'',2,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','yes','no','yes','tcp/80,443,4080,5223,udp/dynamic',0,'ichat-av,sip,ssl,stun,web-browsing,aim-base','','','',0,'no','USA'),(584,'fastmail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80',0,'ssl,web-browsing','','','',0,'yes','USA'),(585,'fasttrack',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/1214,udp/1214',0,'','','','',0,'no','USA'),(586,'fastviewer',NULL,'',3,'networking','remote-access','client-server','yes','no','no','yes','no','yes','no','yes','tcp/80,443,5000',0,'','','ssl,web-browsing','',0,'yes','USA'),(591,'feidian',NULL,'',5,'media','photo-video','peer-to-peer','yes','yes','yes','yes','no','no','yes','yes','tcp/80,udp/53125',0,'web-browsing','','','',0,'no','USA'),(593,'fetion-base',NULL,'',2,'collaboration','instant-messaging','client-server','yes','no','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'ssl,stun,web-browsing','','','fetion',0,'no','China'),(594,'fetion-audio-video',NULL,'',2,'collaboration','voip-video','client-server','yes','no','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'fetion-base,stun,ssl,web-browsing','','','fetion',0,'yes','China'),(595,'fetion-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'fetion-base,ssl,stun,web-browsing','','','fetion',0,'yes','China'),(600,'fileguri',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','no','no','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','Korea'),(601,'filemail',NULL,'',5,'general-internet','file-sharing','browser-based','yes','yes','yes','yes','yes','no','yes','yes','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','Norway'),(604,'filer.cx',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','yes','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(606,'filesanywhere',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/443',0,'ftp','','ssl','',0,'yes','USA'),(609,'filestack-base',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','filestack',0,'no',''),(610,'filestack-downloading',NULL,'',4,'general-internet','internet-utility','client-server','no','yes','yes','yes','yes','no','no','no','tcp/443',0,'filestack-base,ssl,web-browsing','','','filestack',0,'yes',''),(611,'filestack-uploading',NULL,'',3,'general-internet','internet-utility','client-server','no','yes','no','yes','yes','no','no','no','tcp/443',0,'filestack-base,ssl,web-browsing','','','filestack',0,'yes',''),(613,'fileswire',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','no','tcp/dynamic,udp/dynamic',0,'gnutella,web-browsing','','','',0,'no','USA'),(618,'firefox-update',NULL,'',3,'business-systems','software-update','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'','','web-browsing','',0,'no','USA'),(620,'firstclass',NULL,'',2,'collaboration','social-business','client-server','no','no','no','yes','no','no','no','yes','tcp/80,443,510',0,'ssl,web-browsing','','','',0,'yes','USA'),(623,'flashget',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/80,udp/dynamic',0,'bittorrent,emule,mms,rtsp,web-browsing','','','',0,'no','USA'),(626,'flickr-base',NULL,'',3,'media','photo-video','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','flickr',0,'no','USA'),(627,'flickr-uploading',NULL,'',3,'media','photo-video','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'flickr-base,ssl,web-browsing','','','flickr',0,'no','USA'),(629,'flixwagon-base',NULL,'',1,'media','photo-video','client-server','no','no','no','no','no','no','no','no','tcp/80',0,'web-browsing','','','flixwagon',0,'no','USA'),(630,'flixwagon-broadcasting',NULL,'',2,'media','photo-video','client-server','yes','yes','no','no','no','no','no','no','tcp/80,82,86',0,'flixwagon-base,web-browsing','','','flixwagon',0,'no','USA'),(631,'flixwagon-downloading',NULL,'',3,'media','photo-video','client-server','yes','yes','no','yes','no','no','no','no','tcp/80',0,'flixwagon-base,web-browsing','','','flixwagon',0,'no','USA'),(632,'flixwagon-posting',NULL,'',1,'collaboration','social-networking','client-server','no','no','no','no','no','no','no','no','tcp/80',0,'flixwagon-base,web-browsing','','','flixwagon',0,'no','USA'),(633,'flixwagon-sharing',NULL,'',1,'collaboration','social-networking','client-server','no','no','no','no','no','no','no','no','tcp/80',0,'flixwagon-base,web-browsing','','','flixwagon',0,'no','USA'),(634,'flock',NULL,'',4,'collaboration','instant-messaging','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443,993',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(636,'fluxiom',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(638,'fogbugz',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'web-browsing','','','',0,'yes','USA'),(643,'forticlient-update',NULL,'',2,'business-systems','software-update','client-server','yes','no','no','no','yes','no','no','no','tcp/80',0,'','','web-browsing','',0,'no','USA'),(650,'foxy',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/80,udp/dynamic',0,'web-browsing,gnutella,neonet','','','',0,'no','USA'),(655,'freenet',NULL,'',5,'networking','encrypted-tunnel','peer-to-peer','yes','yes','yes','yes','yes','yes','yes','no','udp/dynamic',0,'','','','',0,'no','USA'),(656,'freepp-mobile',NULL,'',3,'collaboration','voip-video','client-server','no','yes','no','yes','yes','no','no','yes','tcp/80,udp/dynamic',0,'asterisk-iax,web-browsing','','','',0,'yes','China'),(657,'freshbooks',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'yes',''),(658,'freshsales',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(662,'fring',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'ssl,web-browsing','','','',0,'yes','USA'),(663,'front',NULL,'',2,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing,websocket','','','',0,'yes',''),(669,'fuze-meeting-base',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','no','no','no','yes','no','no','no','tcp/443,dynamic',0,'rtcp,rtp-base,sip,ssl,stun,vidyo,web-browsing','','','fuze-meeting',0,'yes','USA'),(670,'fuze-meeting-desktop-sharing',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','yes','no','no','no','no','no','no','tcp/dynamic',0,'fuze-meeting-base,rtcp,rtp-base,sip,ssl,stun,vidyo,web-browsing','','','fuze-meeting',0,'yes','USA'),(671,'fuze-meeting-file-sharing',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/443',0,'fuze-meeting-base,ssl,web-browsing,rtcp,rtp-base,sip,stun,vidyo','','','fuze-meeting',0,'yes','USA'),(676,'gatherplace-base',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','no','no','no','yes','no','no','yes','tcp/443,80,udp/4569',0,'ssl,web-browsing','','','gatherplace',0,'yes','USA'),(677,'gatherplace-desktop-sharing',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','yes','no','no','no','no','yes','yes','tcp/443',0,'gatherplace-base,ssl,web-browsing','','','gatherplace',0,'yes','USA'),(682,'generic-p2p',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','udp/dynamic',0,'','','','',0,'no','USA'),(683,'genesys-base',NULL,'',4,'collaboration','internet-conferencing','client-server','yes','yes','no','no','yes','yes','no','yes','tcp/443,80',0,'ssl,web-browsing','','','genesys',0,'no','USA'),(684,'genesys-desktop-sharing',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','yes','no','no','no','no','yes','yes','tcp/443',0,'genesys-base,ssl,web-browsing','','','genesys',0,'yes','USA'),(690,'git-uploading',NULL,'',3,'business-systems','general-business','client-server','no','no','no','yes','yes','yes','no','yes','tcp/443,80',0,'git-base,ssl,web-browsing','','','git',0,'yes','USA'),(691,'github-base',NULL,'',2,'business-systems','management','client-server','no','no','no','yes','no','yes','no','yes','tcp/22,80,443,9418',0,'git-base,ssh,ssl,web-browsing','','','github',0,'yes','USA'),(692,'github-downloading',NULL,'',2,'business-systems','management','client-server','no','no','no','yes','yes','no','no','no','tcp/443',0,'github-base,ssl,web-browsing,git-base,ssh','','','github',0,'yes',''),(693,'github-editing',NULL,'',2,'business-systems','management','client-server','no','no','no','no','yes','no','no','yes','tcp/443',0,'github-base,ssl,web-browsing,git-base,ssh','','','github',0,'yes',''),(694,'github-posting',NULL,'',2,'business-systems','management','client-server','no','no','no','no','yes','no','no','yes','tcp/443',0,'github-base,ssl,web-browsing,git-base,ssh','','','github',0,'yes',''),(695,'github-uploading',NULL,'',3,'business-systems','management','client-server','no','no','no','yes','yes','no','no','yes','tcp/443',0,'github-base,ssl,git-base,ssh,web-browsing','','web-browsing','github',0,'yes','USA'),(698,'gizmo',NULL,'',5,'collaboration','voip-video','peer-to-peer','yes','yes','yes','yes','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(701,'globalmeet-base',NULL,'',2,'collaboration','internet-conferencing','client-server','no','no','no','no','yes','yes','no','no','tcp/443,tcp/80',0,'rtmp,sip,ssl,web-browsing,websocket','','','globalmeet',0,'yes','USA'),(702,'globalmeet-file-transfer',NULL,'',2,'collaboration','internet-conferencing','client-server','no','no','no','yes','yes','no','no','no','tcp/443',0,'globalmeet-base,ssl,web-browsing,rtmp,sip,websocket','','','globalmeet',0,'yes','USA'),(704,'gmail-base',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','yes','no','yes','tcp/80,443,465,587,993,995',0,'google-base','','ssl,web-browsing','gmail',0,'yes','USA'),(705,'gmail-call-phone',NULL,'',1,'collaboration','voip-video','browser-based','no','no','no','no','no','no','no','no','udp/19525,dynamic',0,'','','','gmail',0,'no','USA'),(706,'gmail-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'google-base','','','gmail',0,'no','USA'),(707,'gmail-downloading',NULL,'',2,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'gmail-base,ssl,web-browsing,google-base','','','gmail',0,'yes',''),(708,'gmail-drive',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'gmail-base,google-base','','','',0,'yes','USA'),(709,'gmail-enterprise',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/443,tcp/80',0,'gmail-base,web-browsing,google-base','','','gmail',0,'yes','USA'),(710,'gmail-posting',NULL,'',2,'collaboration','email','browser-based','no','no','no','no','yes','no','no','yes','tcp/443',0,'ssl,web-browsing','','','gmail',0,'yes',''),(711,'gmail-uploading',NULL,'',2,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'gmail-base,ssl,web-browsing,google-base','','','gmail',0,'yes',''),(712,'gmail-video-chat',NULL,'',2,'collaboration','voip-video','browser-based','yes','yes','no','no','no','no','no','yes','tcp/dynamic,udp/19525,dynamic',0,'google-base,stun,vidyo,rtcp,rtp-base,ssl','','','gmail',0,'no','USA'),(714,'gmx-mail',NULL,'',4,'collaboration','email','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443,465,587,993,995',0,'ssl,web-browsing','','','',0,'yes','USA'),(716,'gnunet',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/80,2086,udp/2086',0,'','','','',0,'no','USA'),(717,'gnutella',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','yes','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(719,'goboogy',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/5325,udp/5325',0,'','','','',0,'no','USA'),(721,'gomeetnow',NULL,'',2,'collaboration','internet-conferencing','client-server','no','no','no','yes','no','no','no','yes','tcp/8889,443,80,udp/8889',0,'ssl,web-browsing','','','',0,'yes','USA'),(724,'gooddata',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes',''),(726,'google-analytics',NULL,'',2,'general-internet','internet-utility','browser-based','yes','no','no','no','no','no','no','yes','tcp/80,443',0,'','','web-browsing','',0,'no','USA'),(727,'google-app-engine',NULL,'',3,'general-internet','internet-utility','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/80,443',0,'google-base','','','',0,'no','USA'),(728,'google-app-engine-uploading',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','yes','no','no','yes','yes','tcp/443',0,'google-app-engine,google-base','','','',0,'yes','USA'),(729,'google-base',NULL,'',4,'general-internet','internet-utility','browser-based','no','no','yes','yes','yes','yes','no','no','tcp/80,443,5222-5224,5228,5229',0,'','','ssl,web-browsing','',0,'no','USA'),(730,'google-buzz',NULL,'',4,'collaboration','instant-messaging','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80',0,'google-base','','','',0,'no','USA'),(731,'google-cache',NULL,'',3,'general-internet','internet-utility','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80',0,'google-base','','','',0,'no','USA'),(732,'google-calendar-base',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'google-base','','','google-calendar',0,'yes','USA'),(733,'google-calendar-enterprise',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'google-base,google-calendar-base','','','google-calendar',0,'yes','USA'),(734,'google-calendar-posting',NULL,'',3,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'google-calendar-base,google-base','','','google-calendar',0,'yes',''),(735,'google-classroom',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'google-base,google-docs-base,google-drive-web,google-docs-editing,google-docs-uploading','','','',0,'yes','USA'),(736,'google-cloud-messaging',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','no','no','no','no','tcp/5228,5229,5230,443',0,'google-base','','ssl','',0,'no','USA'),(737,'google-cloud-print',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'google-base','','jabber,ssl,web-browsing','',0,'yes','USA'),(738,'google-cloud-storage-base',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','no','yes','no','no','tcp/80,443',0,'google-base','','','google-cloud-storage',0,'yes','USA'),(739,'google-cloud-storage-upload',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','no','no','yes','yes','tcp/80,443',0,'google-base,google-cloud-storage-base','','','google-cloud-storage',0,'yes','USA'),(740,'google-desktop',NULL,'',4,'general-internet','internet-utility','client-server','yes','no','no','yes','yes','no','yes','yes','tcp/80',0,'google-base','','web-browsing','',0,'no','USA'),(741,'google-docs-base',NULL,'',5,'business-systems','office-programs','browser-based','yes','no','yes','yes','yes','no','no','yes','tcp/443,tcp/80',0,'google-base','','','google-docs',0,'yes','USA'),(742,'google-docs-downloading',NULL,'',5,'business-systems','office-programs','browser-based','yes','yes','yes','yes','yes','no','no','yes','tcp/80,443',0,'google-base,google-docs-base','','','google-docs',0,'yes',''),(743,'google-docs-editing',NULL,'',4,'business-systems','office-programs','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80,443',0,'google-base,google-docs-base','','','google-docs',0,'yes','USA'),(744,'google-docs-enterprise',NULL,'',5,'business-systems','office-programs','browser-based','yes','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'google-base,google-docs-base,google-docs-editing,google-docs-uploading','','','google-docs',0,'yes','USA'),(745,'google-docs-posting',NULL,'',4,'business-systems','office-programs','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80,443',0,'','','','google-docs',0,'yes',''),(746,'google-docs-sharing',NULL,'',4,'business-systems','office-programs','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80,443',0,'','','','google-docs',0,'yes',''),(747,'google-docs-uploading',NULL,'',5,'business-systems','office-programs','browser-based','yes','yes','yes','yes','yes','no','no','yes','tcp/80,443',0,'google-base,google-docs-base','','','google-docs',0,'yes','USA'),(748,'google-drive-web',NULL,'',5,'general-internet','file-sharing','browser-based','yes','no','yes','yes','yes','no','no','yes','tcp/443,80',0,'google-base,google-docs-base,google-docs-editing,google-docs-uploading','','','',0,'yes','USA'),(749,'google-duo',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','yes','tcp/443,udp/19305',0,'google-base,ssl,stun','','','',0,'no',''),(750,'google-earth',NULL,'',3,'general-internet','internet-utility','client-server','yes','yes','no','yes','no','no','no','yes','tcp/80,443',0,'google-base','','','',0,'no','USA'),(751,'google-finance-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','yes','yes','tcp/80,443',0,'google-base','','ssl,web-browsing','',0,'no','USA'),(752,'google-hangouts-base',NULL,'',3,'collaboration','voip-video','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/80,443,5222',0,'google-base,google-plus-base,jabber,rtcp,rtp-base,stun,vidyo,ssl','','','google-hangouts',0,'yes','USA'),(753,'google-hangouts-audio-video',NULL,'',3,'collaboration','voip-video','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/80,443,udp/19302-19309',0,'google-base,google-hangouts-base,google-plus-base,jabber,rtcp,rtp-base,stun,vidyo,ssl','','','google-hangouts',0,'yes','USA'),(754,'google-hangouts-chat',NULL,'',4,'collaboration','instant-messaging','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'google-base,google-hangouts-base,google-plus-base,jabber,rtcp,rtp-base,stun,vidyo,ssl','','','google-hangouts',0,'no','USA'),(755,'google-keep',NULL,'',2,'general-internet','internet-utility','client-server','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'google-drive-web,google-voice-actions,ssl,web-browsing,google-base,google-docs-base,google-docs-editing,google-docs-uploading','','','',0,'yes','USA'),(756,'google-lively',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/8182,udp/3128,8182',0,'google-base','','','',0,'no','USA'),(757,'google-location-service',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','yes','yes','tcp/443',0,'google-base','','','',0,'no','USA'),(758,'google-maps',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','yes','no','yes','tcp/80,443',0,'google-base','','','',0,'no','USA'),(759,'google-music',NULL,'',3,'media','audio-streaming','client-server','yes','yes','no','yes','no','no','no','no','tcp/443,80',0,'google-base','','','',0,'no','USA'),(760,'google-photos',NULL,'',3,'media','photo-video','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'google-base','','','',0,'yes',''),(761,'google-picasa',NULL,'',3,'media','photo-video','client-server','yes','yes','no','yes','no','no','no','yes','tcp/80,443',0,'google-base','','','',0,'no','USA'),(762,'google-play',NULL,'',3,'general-internet','internet-utility','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/443,80,5228,udp/5228',0,'flash,google-base,google-plus-base,youtube-base,web-browsing,jabber,ssl','','','',0,'no','USA'),(763,'google-plus-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/443',0,'google-base,jabber,ssl','','','google-plus',0,'no','USA'),(764,'google-plus-email',NULL,'',2,'collaboration','email','browser-based','no','no','no','no','yes','no','no','yes','tcp/443',0,'google-base','','','',0,'yes','USA'),(765,'google-plus-posting',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443',0,'google-base,google-plus-base,jabber,ssl','','','google-plus',0,'no','USA'),(766,'google-safebrowsing',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'google-base','','','',0,'no','USA'),(767,'google-spaces-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,udp/443',0,'google-base','','','google-spaces',0,'no',''),(768,'google-spaces-posting',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'google-base,google-spaces-base','','','google-spaces',0,'no',''),(769,'google-talk-base',NULL,'',4,'collaboration','instant-messaging','client-server','yes','no','yes','no','yes','yes','no','yes','tcp/80,443,5222,5223,5228',0,'google-base','','jabber,web-browsing','google-talk',0,'no','USA'),(770,'gtalk-file-transfer',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','no','yes','yes','yes','yes','no','yes','tcp/dynamic,udp/dynamic',0,'stun','','','google-talk',0,'no','USA'),(771,'google-talk-gadget',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'no','USA'),(772,'google-toolbar',NULL,'',2,'general-internet','internet-utility','client-server','no','yes','no','no','no','no','yes','yes','tcp/80',0,'google-base','','','',0,'no','USA'),(773,'google-translate-base',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','yes','no','yes','no','yes','tcp/80,443',0,'google-base','','','google-translate',0,'no','USA'),(774,'google-translate-auto',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'google-base','','','google-translate',0,'no','USA'),(775,'google-translate-manual',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','yes','yes','tcp/80,443',0,'google-base','','','google-translate',0,'no','USA'),(776,'google-update',NULL,'',3,'business-systems','software-update','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'google-base','','','',0,'no','USA'),(777,'google-video-base',NULL,'',3,'media','photo-video','browser-based','no','yes','no','no','yes','yes','no','yes','tcp/80',0,'google-base','','','google-video',0,'no','USA'),(778,'google-video-enterprise',NULL,'',3,'media','photo-video','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'','','','google-video',0,'no','USA'),(779,'google-voice-actions',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','no','no','no','yes','tcp/14259,443',0,'google-base','','web-browsing','',0,'no','USA'),(780,'google-wave',NULL,'',3,'collaboration','internet-conferencing','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/443,80',0,'','','','',0,'no','USA'),(782,'gotoassist',NULL,'',2,'networking','remote-access','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443,8200',0,'ssl,web-browsing','','','',0,'yes','USA'),(784,'gotomeeting',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','no','no','yes','no','no','yes','yes','tcp/80,443,1853,udp/1853',0,'citrix,citrix-jedi,ssl,web-browsing','','','',0,'yes','USA'),(785,'gotomypc-base',NULL,'',2,'networking','remote-access','client-server','yes','no','no','no','no','no','yes','yes','tcp/dynamic',0,'citrix-jedi,ssl,web-browsing','','','gotomypc',0,'yes','USA'),(786,'gotomypc-desktop-sharing',NULL,'',2,'networking','remote-access','client-server','yes','yes','no','no','no','no','no','yes','tcp/443',0,'gotomypc-base,ssl,citrix-jedi,web-browsing','','citrix-jedi','gotomypc',0,'yes','USA'),(787,'gotomypc-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','no','no','no','yes','tcp/443,8200',0,'gotomypc-base,ssl,citrix-jedi,web-browsing','','citrix-jedi','gotomypc',0,'yes','USA'),(788,'gotomypc-printing',NULL,'',2,'networking','remote-access','client-server','yes','no','no','no','no','no','no','yes','tcp/443,8200',0,'gotomypc-base,ssl,citrix-jedi,web-browsing','','citrix-jedi','gotomypc',0,'yes','USA'),(789,'gotomypc-remote-control',NULL,'',2,'networking','remote-access','client-server','yes','no','no','no','no','no','no','yes','tcp/443,8200',0,'citrix-jedi,gotomypc-base,ssl,web-browsing','','','gotomypc',0,'yes','USA'),(790,'gotowebinar-base',NULL,'',1,'collaboration','internet-conferencing','client-server','no','no','no','no','yes','no','no','no','tcp/80,443,udp/1853',0,'citrix-jedi,gotomeeting,ssl,web-browsing,citrix','','','gotowebinar',0,'yes',''),(791,'gotowebinar-downloading',NULL,'',2,'collaboration','internet-conferencing','client-server','no','no','no','yes','yes','no','no','no','tcp/443',0,'gotowebinar-base,citrix-jedi,gotomeeting,ssl,web-browsing,citrix','','','gotowebinar',0,'yes',''),(792,'gotowebinar-uploading',NULL,'',2,'collaboration','internet-conferencing','client-server','no','no','no','yes','yes','no','no','no','tcp/443',0,'gotowebinar-base,citrix-jedi,gotomeeting,ssl,web-browsing,citrix','','','gotowebinar',0,'yes',''),(800,'ms-groove',NULL,'',4,'business-systems','office-programs','peer-to-peer','yes','no','yes','yes','no','no','yes','yes','tcp/80,2492',0,'ssl,web-browsing','','','',0,'no','USA'),(804,'gtalk-voice',NULL,'',4,'collaboration','voip-video','peer-to-peer','yes','yes','yes','no','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'google-talk-base,stun,google-base','','','google-talk',0,'no','USA'),(817,'h.248',NULL,'',3,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','no','no','yes','udp/dynamic',0,'','','','',0,'no','USA'),(820,'hamachi',NULL,'',5,'networking','encrypted-tunnel','peer-to-peer','yes','no','yes','yes','yes','yes','yes','yes','tcp/12975,10080,udp/17771',0,'web-browsing','','','',0,'no','USA'),(821,'hamicloud',NULL,'',3,'general-internet','internet-utility','browser-based','no','no','no','yes','yes','no','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(829,'highrise',NULL,'',1,'business-systems','erp-crm','browser-based','no','no','no','no','no','no','no','yes','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(830,'hightail-base',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','hightail',0,'yes','USA'),(831,'hightail-uploading',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/443',0,'hightail-base,ssl','','web-browsing','hightail',0,'yes','USA'),(832,'hinet-webmail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','Taiwan'),(834,'hipchat-base',NULL,'',2,'collaboration','instant-messaging','client-server','no','yes','no','yes','no','no','no','no','tcp/80,443,5222,5223,udp/dynamic',0,'rtmfp,ssl','','jabber,web-browsing','hipchat',0,'yes','USA'),(835,'hipchat-audio-video',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','yes','udp/443,540,541',0,'hipchat-base,rtcp,rtp-base,ssl,stun,rtmfp','','jabber,web-browsing','hipchat',0,'no','USA'),(836,'hipchat-downloading',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'hipchat-base,ssl,web-browsing,rtmfp','','','hipchat',0,'yes',''),(837,'hipchat-editing',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'hipchat-base,ssl,web-browsing,rtmfp','','','hipchat',0,'yes',''),(839,'hipchat-posting',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'hipchat-base,ssl,web-browsing,rtmfp','','','hipchat',0,'yes',''),(840,'hipchat-sharing',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'hipchat-base,ssl,web-browsing,rtmfp','','','hipchat',0,'yes',''),(841,'hipchat-uploading',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'hipchat-base,ssl,web-browsing,rtmfp','','','hipchat',0,'yes',''),(848,'hootsuite',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(856,'hotmail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/443,995,tcp/80',0,'office365-consumer-access,silverlight,ssl,web-browsing','','','',0,'no','USA'),(865,'hp-virtual-rooms',NULL,'',2,'collaboration','internet-conferencing','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443,5228',0,'ssl,web-browsing','','','',0,'yes','USA'),(873,'hubspot',NULL,'',2,'business-systems','marketing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'flash,ssl,web-browsing','','','',0,'yes',''),(874,'huddle-base',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','no','yes','no','no','tcp/443,80',0,'ssl,web-browsing','','','huddle',0,'yes','USA'),(875,'huddle-uploading',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','yes','no','no','no','no','tcp/443,80',0,'huddle-base,ssl,web-browsing','','','huddle',0,'yes','USA'),(877,'hulu-base',NULL,'',2,'media','photo-video','browser-based','yes','yes','no','no','no','no','no','yes','tcp/1935,tcp/443,tcp/80',0,'rtsp,web-browsing','','','hulu',0,'no','USA'),(878,'hulu-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/1935,tcp/443,tcp/80',0,'hulu-base,rtsp,web-browsing','','','hulu',0,'no','USA'),(879,'hushmail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443',0,'web-browsing','','','',0,'yes','USA'),(880,'hyves-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/80,443',0,'ssl,web-browsing','','','hyves',0,'no','Netherlands'),(881,'hyves-chat',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','no','yes','no','no','yes','tcp/80,5222',0,'web-browsing','','jabber','hyves',0,'no','Netherlands'),(882,'hyves-games',NULL,'',2,'media','gaming','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','hyves',0,'no','Netherlands'),(883,'hyves-mail',NULL,'',3,'collaboration','email','browser-based','no','no','yes','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','hyves',0,'yes','Netherlands'),(884,'hyves-music',NULL,'',2,'media','audio-streaming','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','hyves',0,'no','Netherlands'),(888,'ibackup',NULL,'',1,'business-systems','storage-backup','client-server','no','yes','no','no','no','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(903,'ichat-av',NULL,'',3,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','no','no','yes','udp/dynamic',0,'aim-base,ssl,web-browsing','','','',0,'no','USA'),(904,'icloud-base',NULL,'',2,'general-internet','internet-utility','client-server','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','icloud',0,'yes','USA'),(905,'icloud-mail',NULL,'',2,'collaboration','email','client-server','no','no','no','yes','no','no','no','yes','tcp/80,443,993,587',0,'icloud-base,imap,smtp,ssl,web-browsing','','','icloud',0,'yes','USA'),(920,'igloo-software',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(932,'imeet-base',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','yes','no','no','yes','no','no','no','tcp/80,443',0,'flash,rtmp,ssl,web-browsing','','','imeet',0,'yes','USA'),(933,'imeet-file-transfer',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'imeet-base,ssl,web-browsing,flash,rtmp','','','imeet',0,'yes','USA'),(934,'imesh',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/4000-4999,6346-6351,4661,4662,4671,80,443,1863,udp/6346-6351,4665,4672',0,'ssl,web-browsing','','','',0,'no','USA'),(935,'imgur-base',NULL,'',4,'media','photo-video','browser-based','no','no','no','yes','yes','yes','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','imgur',0,'no','USA'),(936,'imgur-uploading',NULL,'',2,'media','photo-video','browser-based','no','no','no','yes','no','no','yes','yes','tcp/80,443',0,'imgur-base,ssl,web-browsing','','','imgur',0,'no','USA'),(944,'informatica-cloud',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','yes','no','no','no','no','tcp/443',0,'ssl','','','',0,'yes',''),(947,'insightly-crm',NULL,'',3,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(948,'instagram-base',NULL,'',2,'media','photo-video','client-server','no','no','no','yes','no','no','no','yes','tcp/443,80',0,'apple-maps,google-maps,web-browsing,google-base','','ssl','instagram',0,'no','USA'),(949,'instagram-upload',NULL,'',2,'media','photo-video','client-server','no','no','no','yes','no','no','no','yes','tcp/443,80',0,'apple-maps,google-maps,instagram-base,ssl,web-browsing,google-base','','','instagram',0,'no','USA'),(953,'intacct',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'web-browsing','','ssl','',0,'yes','USA'),(954,'intercall',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(956,'intuit-quickbase',NULL,'',1,'business-systems','database','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'web-browsing','','ssl','',0,'yes','USA'),(963,'ip-messenger-base',NULL,'',1,'collaboration','instant-messaging','peer-to-peer','no','no','no','yes','no','no','no','no','tcp/dynamic,udp/dynamic',0,'','','','ip-messenger',0,'no','USA'),(964,'ip-messenger-file-transfer',NULL,'',1,'general-internet','file-sharing','peer-to-peer','no','no','no','yes','no','no','no','no','tcp/dynamic',0,'ip-messenger-base','','','ip-messenger',0,'no','USA'),(993,'issuu-base',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','issuu',0,'no','USA'),(994,'issuu-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80',0,'issuu-base,web-browsing','','','issuu',0,'no','USA'),(996,'itunes-base',NULL,'',3,'media','audio-streaming','client-server','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','itunes',0,'no','USA'),(997,'itunes-appstore',NULL,'',2,'general-internet','internet-utility','client-server','no','yes','no','no','yes','no','no','yes','tcp/80',0,'itunes-base,web-browsing,ssl','','','itunes',0,'no','USA'),(998,'itunes-mediastore',NULL,'',3,'media','audio-streaming','client-server','no','yes','no','yes','yes','no','no','yes','tcp/80',0,'itunes-base,web-browsing,ssl','','','itunes',0,'no','USA'),(1006,'jdi-onlinebackupstorage',NULL,'',2,'business-systems','storage-backup','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'google-cloud-storage-base,ssl,web-browsing,google-base','','','',0,'yes','USA'),(1009,'jira',NULL,'',3,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1012,'jobvite',NULL,'',3,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl','','','',0,'yes','USA'),(1013,'join-me-base',NULL,'',2,'collaboration','internet-conferencing','browser-based','yes','no','no','no','yes','no','no','no','tcp/443,80,udp/dynamic',0,'rtcp,rtp-base,ssl,web-browsing','','','join-me',0,'yes','USA'),(1014,'join-me-file-transfer',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/443',0,'join-me-base,ssl,web-browsing,rtcp,rtp-base','','','join-me',0,'yes','USA'),(1015,'joost',NULL,'',2,'media','photo-video','peer-to-peer','yes','yes','no','no','no','no','no','yes','tcp/443,tcp/80',0,'web-browsing','','','',0,'no','USA'),(1019,'jumpshare-base',NULL,'',2,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443,3000',0,'ssl,web-browsing','','','jumpshare',0,'no',''),(1020,'jumpshare-uploading',NULL,'',2,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'jumpshare-base,ssl,web-browsing','','','jumpshare',0,'no',''),(1021,'jungledisk',NULL,'',2,'business-systems','storage-backup','client-server','no','yes','no','yes','no','no','no','yes','tcp/443,80',0,'ssl','','web-browsing','',0,'yes','USA'),(1024,'jxta',NULL,'',4,'networking','infrastructure','peer-to-peer','yes','no','no','yes','yes','yes','no','no','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1026,'kaixin-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80',0,'kaixin-base,web-browsing','','','kaixin',0,'no','USA'),(1027,'kaixin-mail',NULL,'',2,'collaboration','email','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'kaixin-base,web-browsing','','','kaixin',0,'yes','USA'),(1028,'kaixin001-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/80',0,'web-browsing','','','kaixin001',0,'no','USA'),(1029,'kaixin001-mail',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','kaixin001',0,'yes','USA'),(1030,'kakaotalk-base',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','no','no','no','tcp/dynamic',0,'web-browsing','','ssl','kakaotalk',0,'no','Korea'),(1031,'kakaotalk-audio-chat',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','no','no','no','no','tcp/dynamic,udp/dynamic',0,'kakaotalk-base,rtcp,rtp-base,web-browsing','','ssl','kakaotalk',0,'yes','USA'),(1032,'kakaotalk-file-transfer',NULL,'',2,'collaboration','instant-messaging','client-server','no','yes','no','yes','no','no','no','no','tcp/dynamic',0,'kakaotalk-base,web-browsing','','ssl','kakaotalk',0,'no','USA'),(1033,'kanban-tool',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','USA'),(1037,'kazaa',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','yes','yes','yes','tcp/1214,1903',0,'web-browsing','','','',0,'no','USA'),(1043,'kaixin-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/80',0,'web-browsing','','','kaixin',0,'no','USA'),(1050,'kontiki',NULL,'',3,'media','photo-video','peer-to-peer','no','yes','no','no','yes','yes','no','yes','tcp/dynamic,udp/dynamic',0,'bbc-iplayer,web-browsing,rtmpt','','','',0,'no','USA'),(1052,'korea-webmail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'web-browsing','','','',0,'yes','Korea'),(1055,'kt-ucloud',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes','Korea'),(1057,'kugoo',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1067,'lantern',NULL,'',1,'networking','proxy','peer-to-peer','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'no',''),(1070,'lastpass',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','yes','yes','tcp/80,443',0,'','','ssl,web-browsing','',0,'no','USA'),(1076,'leapfile',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(1081,'lifesize',NULL,'',2,'collaboration','voip-video','client-server','no','yes','no','no','no','yes','yes','yes','tcp/dynamic',0,'h.225,h.245,sip','','ssl','',0,'yes','USA'),(1084,'linkedin-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','linkedin',0,'no','USA'),(1085,'linkedin-apps',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'linkedin-base','','web-browsing','linkedin',0,'no','USA'),(1086,'linkedin-intro',NULL,'',1,'collaboration','email','browser-based','no','no','no','yes','no','no','no','no','tcp/143,443,587',0,'imap,linkedin-base,smtp','','ssl','linkedin',0,'yes','USA'),(1087,'linkedin-mail',NULL,'',2,'collaboration','email','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'linkedin-base','','web-browsing','linkedin',0,'yes','USA'),(1088,'linkedin-posting',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'linkedin-base','','web-browsing','linkedin',0,'no','USA'),(1089,'litecoin',NULL,'',1,'general-internet','internet-utility','peer-to-peer','no','no','no','no','yes','no','no','no','tcp/9333',0,'stratum-mining-protocol','','','',0,'no','USA'),(1091,'live-meeting',NULL,'',4,'collaboration','internet-conferencing','client-server','yes','no','no','yes','no','yes','yes','yes','tcp/80,443,8057,3478,8000-8100',0,'ssl,stun,web-browsing','','','',0,'yes','USA'),(1092,'live-mesh-base',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','live-mesh',0,'no','USA'),(1093,'live-mesh-remote-desktop',NULL,'',3,'networking','remote-access','client-server','yes','no','no','no','yes','no','no','yes','tcp/80,443,33701',0,'live-mesh-base,ssl,web-browsing','','','live-mesh',0,'yes','USA'),(1094,'live-mesh-sync',NULL,'',4,'general-internet','file-sharing','client-server','yes','yes','no','yes','yes','no','no','yes','tcp/dynamic',0,'live-mesh-base,ssl,web-browsing','','','live-mesh',0,'yes','USA'),(1099,'liveperson',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1104,'logentries',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','no','no','no','no','tcp/443',0,'','','ssl','',0,'yes',''),(1107,'logmein',NULL,'',4,'networking','remote-access','client-server','no','yes','no','yes','yes','yes','no','yes','tcp/80,443,1152,1153,udp/1152,1153',0,'adobe-flash-socketpolicy-server','','ssl,web-browsing','',0,'yes','USA'),(1108,'logmeinrescue',NULL,'',2,'networking','remote-access','client-server','yes','yes','no','no','no','no','no','yes','tcp/80,443,udp/1152,1153,udp/dynamic',0,'ssl,web-browsing','','','',0,'yes','USA'),(1114,'lotuslive-base',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','lotuslive',0,'yes','USA'),(1115,'lotuslive-file-sharing',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'lotuslive-base,ssl,web-browsing','','','lotuslive',0,'yes','USA'),(1116,'lotuslive-inotes',NULL,'',2,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'lotuslive-base,ssl,web-browsing','','','lotuslive',0,'yes','USA'),(1117,'lotuslive-meeting',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/443',0,'ssl,web-browsing','','','lotuslive',0,'yes','USA'),(1118,'lotuslive-meeting-apps-sharing',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','no','no','no','yes','no','no','yes','tcp/443',0,'lotuslive-meeting,ssl,web-browsing','','','lotuslive',0,'yes','USA'),(1119,'lotuslive-meeting-file-sharing',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/443',0,'lotuslive-meeting,ssl,web-browsing','','','lotuslive',0,'yes','USA'),(1123,'lucidpress-base',NULL,'',1,'business-systems','office-programs','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'google-analytics','','ssl,web-browsing','lucidpress',0,'yes',''),(1124,'lucidpress-editing',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'lucidpress-base,google-analytics','','','lucidpress',0,'yes',''),(1129,'magicjack',NULL,'',3,'collaboration','voip-video','client-server','no','yes','yes','no','yes','no','no','yes','tcp/80,443,udp/5070',0,'sip,ssl,web-browsing','','','',0,'yes','USA'),(1131,'mail.com',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','yes','no','yes','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(1132,'mail.ru-base',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','mail.ru',0,'no','Russia'),(1133,'mail.ru-agent-base',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','no','no','no','yes','tcp/80,443,2041,2042',0,'mail.ru-base,ssl,web-browsing','','','mail.ru-agent',0,'no','Russia'),(1134,'mail.ru-agent-file-transfer',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','no','yes','tcp/dynamic',0,'mail.ru-agent-base,mail.ru-base,ssl,web-browsing','','web-browsing','mail.ru-agent',0,'yes','Russia'),(1135,'mail.ru-games',NULL,'',3,'media','gaming','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,843,2041,10999,443',0,'mail.ru-base,mail.ru-agent-base,ssl,web-browsing','','','mail.ru',0,'no','Russia'),(1136,'mail.ru-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'mail.ru-base,ssl,web-browsing','','','mail.ru',0,'yes','Russia'),(1137,'mail.ru-moimir',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'mail.ru-base,web-browsing,ssl','','','mail.ru',0,'no','Russia'),(1139,'mailchimp',NULL,'',4,'business-systems','marketing','browser-based','no','no','yes','yes','yes','no','no','no','tcp/443,tcp/80',0,'ssl,websocket','','web-browsing','',0,'yes',''),(1140,'noteworthy-base',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/dynamic',0,'web-browsing','','','noteworthy',0,'no','USA'),(1141,'noteworthy-admin',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','yes','no','no','no','tcp/80,tcp/dynamic',0,'web-browsing','','','noteworthy',0,'no','USA'),(1144,'manolito',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/18625,udp/41169,udp/41170',0,'web-browsing','','','',0,'no','USA'),(1151,'maytech-base',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','maytech',0,'yes',''),(1152,'maytech-downloading',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'maytech-base,ssl,web-browsing','','','maytech',0,'yes',''),(1153,'maytech-share',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'maytech-base,ssl,web-browsing','','','maytech',0,'yes',''),(1154,'maytech-uploading',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'maytech-base,ssl,web-browsing','','','maytech',0,'yes',''),(1161,'meabox',NULL,'',2,'media','photo-video','peer-to-peer','no','yes','no','yes','no','no','no','yes','tcp/80,3128,udp/3128',0,'web-browsing,fs2you','','','',0,'no','USA'),(1173,'meetup-base',NULL,'',1,'collaboration','social-networking','browser-based','no','no','no','no','no','yes','no','yes','tcp/80,443',0,'ssl,web-browsing','','','meetup',0,'no','USA'),(1174,'meetup-email',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'meetup-base,ssl,web-browsing','','','meetup',0,'no','USA'),(1175,'meetup-forum',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'meetup-base,ssl,web-browsing','','','meetup',0,'no','USA'),(1177,'mega-base',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','no','no','no','yes','tcp/443',0,'','','ssl,web-browsing','mega',0,'yes','USA'),(1178,'megachat',NULL,'',1,'collaboration','instant-messaging','browser-based','no','no','no','no','no','no','no','yes','udp/dynamic',0,'mega-base,rtcp,rtp-base,ssl,stun','','','mega',0,'no','New Zealand'),(1180,'megashare',NULL,'',5,'general-internet','file-sharing','browser-based','yes','yes','yes','yes','yes','no','yes','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(1181,'megashares',NULL,'',5,'general-internet','file-sharing','browser-based','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic',0,'web-browsing','','','',0,'yes','USA'),(1188,'mendeley-base',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','mendeley',0,'yes','USA'),(1189,'mendeley-uploading',NULL,'',4,'general-internet','file-sharing','client-server','no','yes','no','yes','yes','no','yes','yes','tcp/80,443',0,'mendeley-base,ssl,web-browsing','','','mendeley',0,'yes','USA'),(1190,'meraki-cloud-controller',NULL,'',1,'networking','infrastructure','client-server','no','no','no','no','no','no','no','yes','tcp/80,443,993,7734,7752,udp/7351,9350,32768-61000',0,'ssl','','','',0,'yes','USA'),(1198,'meta4',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1207,'microsoft-dynamics-crm',NULL,'',1,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','no','no','tcp/443,tcp/80',0,'ms-office365-base,ssl,web-browsing,windows-azure-base','','','',0,'yes','USA'),(1209,'mikogo',NULL,'',2,'collaboration','internet-conferencing','client-server','yes','no','no','no','yes','no','no','no','tcp/443,80',0,'web-browsing','','','',0,'yes','Germany'),(1215,'miro',NULL,'',3,'media','photo-video','peer-to-peer','yes','yes','no','yes','no','no','yes','no','tcp/80',0,'web-browsing','','','',0,'no','USA'),(1217,'mixi-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','mixi',0,'no','Japan'),(1218,'mixi-posting',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'mixi-base,ssl,web-browsing','','','mixi',0,'no','Japan'),(1249,'moxtra',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'web-browsing,websocket','','ssl','',0,'yes',''),(1250,'mozy',NULL,'',3,'business-systems','storage-backup','client-server','yes','no','no','yes','no','no','no','yes','tcp/80',0,'ipsec-esp-udp,ssl,web-browsing','','','',0,'yes','USA'),(1254,'ms-delve',NULL,'',1,'business-systems','office-programs','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'sharepoint-online,ssl,web-browsing,ms-office365-base','','','',0,'yes',''),(1267,'ms-lync-base',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','no','yes','yes','no','yes','tcp/dynamic,udp/dynamic',0,'ssl,stun','','','ms-lync',0,'no','USA'),(1268,'ms-lync-apps-sharing',NULL,'',1,'collaboration','internet-conferencing','client-server','no','yes','no','no','no','no','no','yes','tcp/dynamic',0,'ms-lync-base,stun,ssl','','','ms-lync',0,'no','USA'),(1269,'ms-lync-audio',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','yes','udp/dynamic',0,'ms-lync-base,rtcp,rtp-base,stun,ssl','','','ms-lync',0,'no','USA'),(1270,'ms-lync-content-sharing',NULL,'',3,'collaboration','internet-conferencing','client-server','no','yes','no','no','yes','no','yes','yes','tcp/443,8057',0,'ms-lync-base,ssl,stun','','','ms-lync',0,'no','USA'),(1271,'ms-lync-file-transfer',NULL,'',2,'general-internet','file-sharing','client-server','no','yes','no','yes','no','no','no','yes','tcp/dynamic',0,'ms-lync-base,stun,ssl','','','ms-lync',0,'no','USA'),(1272,'ms-lync-online',NULL,'',3,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','yes','no','yes','tcp/443,80',0,'ms-office365-base,ssl,stun,web-browsing','','','ms-office365',0,'yes','USA'),(1273,'ms-lync-online-apps-sharing',NULL,'',2,'collaboration','internet-conferencing','browser-based','no','yes','no','no','yes','no','no','yes','tcp/443',0,'ms-lync-online,ssl,web-browsing,ms-office365-base,stun','','','ms-office365',0,'yes','USA'),(1274,'ms-lync-online-file-transfer',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443',0,'ms-lync-online,ssl,web-browsing,ms-office365-base,stun','','','ms-office365',0,'yes','USA'),(1275,'ms-lync-video',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','yes','udp/dynamic',0,'ms-lync-base,ms-lync-audio,rtcp,rtp-base,stun,ssl','','','ms-lync',0,'no','USA'),(1277,'ms-ocs-audio',NULL,'',2,'collaboration','voip-video','peer-to-peer','yes','yes','no','no','no','no','no','yes','udp/dynamic',0,'','','','',0,'no','USA'),(1278,'ms-ocs-file-transfer',NULL,'',2,'general-internet','file-sharing','peer-to-peer','no','no','no','yes','no','no','yes','no','tcp/6891',0,'','','','',0,'no','USA'),(1279,'ms-ocs-video',NULL,'',2,'collaboration','voip-video','peer-to-peer','yes','yes','no','no','no','no','no','yes','udp/dynamic',0,'','','','',0,'no','USA'),(1281,'ms-office365-base',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','ms-office365',0,'yes','USA'),(1282,'ms-onedrive-base',NULL,'',4,'general-internet','file-sharing','client-server','no','yes','no','yes','yes','no','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','ms-onedrive',0,'yes',''),(1283,'ms-onedrive-downloading',NULL,'',4,'general-internet','file-sharing','client-server','no','yes','yes','yes','yes','no','no','yes','tcp/80,443',0,'ms-onedrive-base,ssl,web-browsing','','','ms-onedrive',0,'yes',''),(1284,'ms-onedrive-share',NULL,'',2,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','yes','yes','tcp/80,443',0,'ms-onedrive-base,ssl,web-browsing','','','ms-onedrive',0,'yes',''),(1285,'ms-onedrive-uploading',NULL,'',3,'general-internet','file-sharing','client-server','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ms-onedrive-base,ssl,web-browsing','','','ms-onedrive',0,'yes',''),(1287,'ms-powerbi',NULL,'',1,'business-systems','office-programs','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ms-office365-base,ssl,web-browsing','','','ms-office365',0,'no',''),(1288,'ms-product-activation',NULL,'',1,'business-systems','software-update','client-server','no','no','no','no','no','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','',0,'no','USA'),(1296,'ms-teams',NULL,'',2,'business-systems','office-programs','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ms-office365-base,sharepoint-online,ssl,web-browsing','','','ms-office365',0,'no',''),(1297,'ms-update',NULL,'',4,'business-systems','software-update','client-server','yes','yes','no','yes','yes','yes','no','yes','tcp/80,443,8530,8531',0,'ssl','','web-browsing','',0,'no','USA'),(1304,'msn-base',NULL,'',4,'collaboration','instant-messaging','client-server','no','no','yes','yes','yes','yes','no','yes','tcp/1863,80,7001,443,udp/7001',0,'ssl,web-browsing','','','msn',0,'no','USA'),(1305,'msn-file-transfer',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','no','yes','yes','yes','no','no','yes','tcp/443,1863,1025-65535,udp/1025-65535',0,'web-browsing','','','msn',0,'no','USA'),(1308,'msn-video',NULL,'',3,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','no','no','yes','udp/dynamic',0,'stun','','','msn',0,'no','USA'),(1309,'msn-voice',NULL,'',4,'collaboration','voip-video','peer-to-peer','yes','yes','yes','no','yes','no','no','yes','tcp/1863,80,udp/dynamic',0,'rtcp,ssl,stun,web-browsing','','','msn',0,'no','USA'),(1312,'msnshell',NULL,'',3,'collaboration','instant-messaging','peer-to-peer','no','no','yes','yes','no','no','no','yes','tcp/1863',0,'','','','',0,'no','China'),(1319,'mute',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/4901',0,'','','','',0,'no','USA'),(1322,'mygreenpc',NULL,'',3,'networking','remote-access','client-server','yes','no','no','no','yes','no','yes','no','tcp/443',0,'','','','',0,'yes','USA'),(1323,'mymarkets',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443,8500-8600',0,'ssl,web-browsing','','','',0,'yes','USA'),(1324,'myspace-base',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','yes','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','myspace',0,'no','USA'),(1325,'myspace-im',NULL,'',3,'collaboration','instant-messaging','client-server','yes','no','yes','no','no','no','no','yes','tcp/dynamic',0,'myspace-base,ssl,web-browsing','','','myspace',0,'no','USA'),(1326,'myspace-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/443,tcp/80',0,'myspace-base,web-browsing,ssl','','','myspace',0,'no','USA'),(1327,'myspace-posting',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'myspace-base,ssl,web-browsing','','','myspace',0,'no','USA'),(1328,'myspace-video',NULL,'',1,'media','photo-video','browser-based','no','yes','no','no','no','no','no','no','tcp/80,443',0,'myspace-base,rtmpe,ssl,web-browsing','','','myspace',0,'no','USA'),(1334,'nasuni',NULL,'',2,'business-systems','storage-backup','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl','','','',0,'yes',''),(1337,'nateon-audio-video',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','no','tcp/dynamic,udp/dynamic',0,'nateon-im-base,ssl,web-browsing','','','nateon-im',0,'yes','USA'),(1342,'naver-line',NULL,'',1,'collaboration','voip-video','client-server','no','no','no','no','no','no','no','yes','tcp/443,80,5223,5242,9418,udp/dynamic',0,'rtcp,rtp-base,sip,ssl,stun,web-browsing','','','',0,'yes','Japan'),(1343,'naver-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443,993,587',0,'imap,me2day,smtp,ssl,web-browsing','','','',0,'yes','Korea'),(1344,'naver-ndrive',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80',0,'ssl,web-browsing','','','',0,'yes','Korea'),(1348,'ndmp',NULL,'',4,'business-systems','storage-backup','peer-to-peer','no','yes','no','yes','yes','yes','no','yes','tcp/1025-5000,10000',0,'','','','',0,'no','USA'),(1349,'nefsis',NULL,'',2,'collaboration','voip-video','client-server','no','yes','no','yes','no','no','no','yes','tcp/80,443,22,23,1270,37000',0,'ssl,web-browsing','','','',0,'yes','USA'),(1351,'neonet',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/6346-6351,6881-6999,4661,4662,4671,udp/6346-6351,4665,4672',0,'web-browsing','','','',0,'no','USA'),(1361,'netease-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(1362,'netease-webdisk-base',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','no','yes','no','no','no','tcp/80',0,'ssl,web-browsing','','','netease-webdisk',0,'yes',''),(1363,'netease-webdisk-downloading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80',0,'netease-webdisk-base,web-browsing,ssl','','','netease-webdisk',0,'yes',''),(1364,'netease-webdisk-uploading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80',0,'netease-webdisk-base,web-browsing,ssl','','','netease-webdisk',0,'yes',''),(1365,'netflix-base',NULL,'',3,'media','photo-video','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/80,443',0,'http-audio,http-video,web-browsing','','ssl','netflix',0,'no','USA'),(1366,'netflix-streaming',NULL,'',3,'media','photo-video','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/80,443',0,'netflix-base,web-browsing,http-audio,http-video','','ssl','netflix',0,'no','USA'),(1368,'netfolder',NULL,'',3,'general-internet','file-sharing','peer-to-peer','no','yes','no','yes','no','no','yes','yes','tcp/dynamic',0,'','','','',0,'no','Korea'),(1369,'netload',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(1372,'netop-on-demand',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','yes','no','yes','no','yes','no','no','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(1375,'netspoke',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','no','no','no','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1376,'netsuite',NULL,'',1,'business-systems','erp-crm','browser-based','no','no','no','no','no','no','no','yes','tcp/443',0,'','','','',0,'yes','USA'),(1382,'new-relic',NULL,'',2,'business-systems','management','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','USA'),(1383,'newton-mail',NULL,'',3,'collaboration','email','client-server','no','no','yes','yes','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1393,'ning-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','ning',0,'no','USA'),(1394,'ning-apps',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ning-base,ssl,web-browsing','','','ning',0,'no','USA'),(1395,'ning-mail',NULL,'',2,'collaboration','email','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ning-base,ssl,web-browsing','','','ning',0,'yes','USA'),(1396,'ning-posting',NULL,'',3,'collaboration','web-posting','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ning-base,ssl,web-browsing','','','ning',0,'no','USA'),(1401,'nomadesk',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','yes','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1407,'ntr-support',NULL,'',3,'networking','remote-access','client-server','yes','no','no','yes','no','no','yes','no','tcp/80,443,21,110,11438',0,'pop3,ssl,web-browsing','','','',0,'yes','Spain'),(1413,'octoshape',NULL,'',2,'media','audio-streaming','peer-to-peer','yes','yes','no','no','no','no','no','yes','tcp/80,8247,udp/8247',0,'web-browsing','','','',0,'no','USA'),(1414,'odnoklassniki-base',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','odnoklassniki',0,'no','Russia'),(1415,'odnoklassniki-apps',NULL,'',1,'collaboration','social-networking','browser-based','no','no','no','no','no','no','no','yes','tcp/80,443',0,'odnoklassniki-base,ssl,web-browsing','','','odnoklassniki',0,'no','Russia'),(1416,'odnoklassniki-messaging',NULL,'',1,'collaboration','instant-messaging','browser-based','no','no','no','no','no','no','no','yes','tcp/80,443',0,'odnoklassniki-base,ssl,web-browsing','','','odnoklassniki',0,'no','Russia'),(1417,'odrive',NULL,'',3,'general-internet','file-sharing','client-server','no','yes','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes',''),(1418,'office-live',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','yes','no','yes','tcp/443,tcp/80',0,'web-browsing','','','',0,'yes','USA'),(1419,'office-on-demand',NULL,'',3,'business-systems','office-programs','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/80',0,'ms-office365-base,sharepoint-online,ssl,web-browsing','','','ms-office365',0,'yes','USA'),(1420,'office365-consumer-access',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','no','no','no','no','no','tcp/80, 443',0,'ssl,web-browsing','','','',0,'yes',''),(1421,'office365-enterprise-access',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','no','no','no','no','no','tcp/80, 443',0,'ms-office365-base,ssl,web-browsing','','','',0,'yes',''),(1423,'okta',NULL,'',3,'business-systems','auth-service','browser-based','no','no','yes','no','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'yes','USA'),(1427,'onehub-base',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','onehub',0,'yes','USA'),(1428,'onehub-uploading',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'onehub-base,ssl,web-browsing','','','onehub',0,'yes','USA'),(1429,'onelogin',NULL,'',3,'business-systems','auth-service','browser-based','no','no','yes','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1430,'onepagecrm',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl','','','',0,'yes','USA'),(1433,'oovoo',NULL,'',2,'collaboration','voip-video','peer-to-peer','yes','no','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'ssl','','jabber,web-browsing','',0,'no','USA'),(1439,'openft',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/1215,1216,udp/1215,1216',0,'','','','',0,'no','USA'),(1446,'optimum-webmail',NULL,'',3,'collaboration','email','browser-based','no','no','yes','yes','no','no','no','yes','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(1451,'oracle-eloqua',NULL,'',1,'business-systems','marketing','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1466,'outlook-web-online',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443,587,993,995',0,'ms-office365-base,ssl,web-browsing','','','ms-office365',0,'yes','USA'),(1469,'owncloud',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/80, 443',0,'web-browsing,webdav,ssl','','ssl','',0,'yes','USA'),(1473,'pagerduty',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1474,'paloalto-aperture',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','no','no','no','no','tcp/80, 443',0,'','','ssl,web-browsing','',0,'yes',''),(1479,'paloalto-wildfire-cloud',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','yes','no','no','no','no','tcp/443',0,'','','ssl','',0,'yes','USA'),(1486,'panda-update',NULL,'',1,'business-systems','software-update','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'no','Spain'),(1487,'pando',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','no','tcp/80,443,udp/dynamic',0,'stun','','ssl,web-browsing','',0,'no','USA'),(1494,'paran-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','Korea'),(1497,'pastebin-base',NULL,'',4,'collaboration','web-posting','browser-based','no','no','yes','yes','yes','no','no','no','tcp/80',0,'','','web-browsing','pastebin',0,'no','USA'),(1498,'pastebin-posting',NULL,'',3,'collaboration','web-posting','browser-based','no','no','no','yes','yes','no','yes','no','tcp/80',0,'pastebin-base','','web-browsing','pastebin',0,'no','USA'),(1500,'pathview',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl','','web-browsing','',0,'yes','USA'),(1507,'peercast',NULL,'',1,'media','photo-video','peer-to-peer','no','yes','no','no','no','no','no','yes','tcp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1508,'peerenabler',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/3529-3533,udp/3529-3533',0,'web-browsing','','','',0,'no','USA'),(1511,'perfect-dark',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic',0,'','','','',0,'no','Japan'),(1521,'pichat',NULL,'',1,'collaboration','instant-messaging','peer-to-peer','no','no','no','no','no','no','no','no','tcp/dynamic,udp/dynamic',0,'','','','',0,'no','USA'),(1526,'pingone',NULL,'',1,'business-systems','auth-service','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'google-maps,ssl,web-browsing,google-base','','','',0,'yes','USA'),(1527,'pinterest-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','pinterest',0,'no','USA'),(1528,'pinterest-messaging',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'pinterest-base','','ssl,web-browsing','pinterest',0,'no',''),(1529,'pinterest-posting',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','no','no','yes','yes','tcp/80,443',0,'pinterest-base','','ssl,web-browsing','pinterest',0,'no','USA'),(1531,'pitchengine',NULL,'',2,'business-systems','marketing','browser-based','no','no','no','yes','no','no','yes','no','tcp/80,443',0,'ssl,web-browsing,windows-azure-base','','','',0,'yes',''),(1532,'pivotaltracker-base',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','pivotaltracker',0,'yes','USA'),(1533,'pivotaltracker-downloading',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','yes','no','no','no','no','tcp/80,443',0,'pivotaltracker-base,ssl,web-browsing','','','pivotaltracker',0,'yes','USA'),(1534,'pivotaltracker-uploading',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','yes','no','no','no','no','tcp/80,443',0,'pivotaltracker-base,ssl,web-browsing','','','pivotaltracker',0,'yes','USA'),(1546,'poco',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/2881,5354,udp/8094',0,'','','','',0,'no','USA'),(1547,'podio',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1558,'powow-base',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','no','no','no','no','no','no','yes','tcp/80,443',0,'','','rtmp,ssl,web-browsing','powow',0,'no','USA'),(1559,'powow-file-transfer',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','no','no','no','yes','tcp/443',0,'powow-base','','ssl,web-browsing','powow',0,'no','USA'),(1560,'pp-accelerator',NULL,'',2,'general-internet','file-sharing','peer-to-peer','no','yes','no','yes','no','no','no','yes','udp/dynamic',0,'','','','',0,'no','China'),(1562,'pplive',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'pp-accelerator,web-browsing','','','',0,'no','USA'),(1563,'ppstream',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1565,'prezi-base',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','yes','no','no','no','no','tcp/80,443',0,'adobe-flash-socketpolicy-server,amazon-cloud-drive-uploading,flash,union-procedure-call,web-browsing,amazon-cloud-drive-base,ssl','','ssl','prezi',0,'yes','USA'),(1566,'prezi-posting',NULL,'',1,'business-systems','office-programs','client-server','no','no','no','no','no','no','no','yes','tcp/80,443',0,'prezi-base,adobe-flash-socketpolicy-server,amazon-cloud-drive-uploading,flash,union-procedure-call,web-browsing,amazon-cloud-drive-base,ssl','','ssl,web-browsing','prezi',0,'yes',''),(1567,'prezi-uploading',NULL,'',2,'business-systems','office-programs','client-server','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'prezi-base,prezi-posting,adobe-flash-socketpolicy-server,amazon-cloud-drive-uploading,flash,union-procedure-call,web-browsing,amazon-cloud-drive-base,ssl','','ssl,web-browsing','prezi',0,'yes',''),(1574,'projectplace',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'netviewer,ssl,web-browsing','','','',0,'yes','Sweden'),(1575,'proofhq',NULL,'',2,'business-systems','marketing','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'yes',''),(1576,'proofhub-base',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','proofhub',0,'yes','USA'),(1577,'proofhub-file-transfer',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'proofhub-base,ssl,web-browsing','','','proofhub',0,'yes','USA'),(1584,'pubnub',NULL,'',2,'business-systems','software-development','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1588,'purple-p3',NULL,'',2,'collaboration','voip-video','client-server','no','yes','no','no','yes','no','no','no','tcp/dynamic,udp/dynamic',0,'hovrs,sip,ssl','','ssl,web-browsing','',0,'yes','USA'),(1593,'qdown',NULL,'',5,'general-internet','file-sharing','client-server','yes','yes','yes','yes','yes','no','yes','no','tcp/dynamic',0,'ssl,web-browsing','','','',0,'yes','Korea'),(1595,'qik-base',NULL,'',2,'media','photo-video','client-server','no','yes','no','no','yes','no','no','yes','tcp/dynamic',0,'ssl,web-browsing','','','qik',0,'yes','USA'),(1596,'qik-posting',NULL,'',2,'collaboration','social-networking','client-server','no','no','no','no','yes','no','no','yes','tcp/80',0,'qik-base,web-browsing,ssl','','','qik',0,'yes','USA'),(1597,'qik-sharing',NULL,'',2,'collaboration','social-networking','client-server','no','no','no','no','yes','no','no','yes','tcp/dynamic',0,'qik-base,web-browsing,ssl','','','qik',0,'yes','USA'),(1598,'qik-uploading',NULL,'',2,'media','photo-video','client-server','no','yes','no','yes','no','no','no','yes','tcp/dynamic',0,'qik-base,ssl,web-browsing','','','qik',0,'yes','USA'),(1599,'qik-video-chatting',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'qik-base,ssl,web-browsing','','','qik',0,'yes','USA'),(1600,'qik-viewing',NULL,'',3,'media','photo-video','client-server','no','yes','no','yes','yes','no','no','yes','tcp/80',0,'qik-base,web-browsing,ssl','','','qik',0,'yes','USA'),(1601,'qlikview',NULL,'',2,'business-systems','general-business','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1603,'qq-base',NULL,'',4,'collaboration','instant-messaging','client-server','no','no','yes','yes','yes','yes','no','yes','tcp/80,443,8000,8080,udp/dynamic',0,'ssl,web-browsing','','','qq',0,'no','China'),(1604,'qq-audio-video',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'qq-base,ssl,web-browsing','','','qq',0,'no','China'),(1605,'qq-download',NULL,'',4,'general-internet','file-sharing','peer-to-peer','yes','yes','no','yes','no','yes','yes','yes','tcp/80,443,udp/dynamic',0,'bittorrent,emule,ftp,qq-base,web-browsing,ssl','','','',0,'no','China'),(1606,'qq-file-transfer',NULL,'',5,'general-internet','file-sharing','client-server','yes','yes','yes','yes','no','no','yes','yes','tcp/dynamic,udp/dynamic',0,'qq-base,ssl,web-browsing','','','qq',0,'no','China'),(1608,'qq-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','yes','no','yes','tcp/80,443,12000',0,'','','ssl,web-browsing','',0,'yes','China'),(1609,'qq-rdp',NULL,'',1,'networking','remote-access','client-server','no','no','no','no','no','yes','no','yes','tcp/dynamic,udp/dynamic',0,'qq-base,qq-audio-video,ssl,web-browsing','','','qq',0,'no','USA'),(1610,'qqlive',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','no','no','yes','yes','tcp/80,443,udp/dynamic',0,'qq-base,web-browsing,ssl','','','',0,'no','China'),(1613,'quantum-edge-tms',NULL,'',1,'business-systems','management','browser-based','no','no','no','yes','no','no','no','no','tcp/80',0,'','','web-browsing','',0,'yes','USA'),(1616,'quip',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(1618,'qvod',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','no','yes','yes','tcp/80,udp/80,dynamic',0,'bittorrent,web-browsing','','','',0,'no','USA'),(1621,'rabbit',NULL,'',2,'media','photo-video','browser-based','no','yes','no','no','yes','no','no','no','tcp/80,443,udp/dynamic',0,'ssl,stun,web-browsing','','','',0,'yes',''),(1628,'rally-software',NULL,'',1,'business-systems','management','browser-based','no','no','no','no','no','no','no','no','tcp/443',0,'ssl','','','',0,'yes','USA'),(1629,'rapidshare',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','yes','yes','tcp/80,443',0,'web-browsing','','ssl','',0,'yes','USA'),(1636,'readytalk-base',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','readytalk',0,'yes','USA'),(1637,'readytalk-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','readytalk',0,'yes','USA'),(1638,'readytalk-desktop-sharing',NULL,'',2,'collaboration','internet-conferencing','browser-based','yes','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','readytalk',0,'yes','USA'),(1639,'realtimeboard',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'google-base,ssl,web-browsing','','','',0,'yes',''),(1641,'rebtel',NULL,'',2,'collaboration','voip-video','client-server','no','no','no','no','yes','no','no','yes','tcp/80,443,udp/dynamic',0,'rtcp,rtp-base,web-browsing','','ssl','',0,'yes','USA'),(1643,'reddit-base',NULL,'',1,'collaboration','social-networking','browser-based','no','no','no','no','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','reddit',0,'no','USA'),(1644,'reddit-posting',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','no','no','yes','yes','tcp/80,443',0,'reddit-base,ssl,web-browsing','','','reddit',0,'no','USA'),(1652,'remobo',NULL,'',4,'networking','encrypted-tunnel','peer-to-peer','yes','no','no','yes','no','yes','yes','no','tcp/443,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1653,'remotecall',NULL,'',3,'networking','remote-access','client-server','yes','yes','no','no','yes','no','no','no','tcp/80,443,9660',0,'ssl,web-browsing','','','',0,'yes','USA'),(1654,'remoteview',NULL,'',4,'networking','remote-access','client-server','yes','yes','no','yes','yes','no','no','no','tcp/80,443',0,'remotecall,ssl,web-browsing','','','',0,'yes','USA'),(1655,'renren-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','yes','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','renren',0,'no','China'),(1656,'renren-apps',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'renren-base,web-browsing,ssl','','','renren',0,'no','China'),(1657,'renren-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,25553',0,'renren-base,web-browsing,ssl','','jabber','renren',0,'no','China'),(1659,'renren-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'renren-base,web-browsing,ssl','','','renren',0,'yes','China'),(1660,'renren-music',NULL,'',2,'media','audio-streaming','browser-based','no','yes','no','no','yes','no','no','yes','tcp/80',0,'renren-base,web-browsing,ssl','','','renren',0,'no','China'),(1661,'renren-posting',NULL,'',1,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','no','tcp/80',0,'renren-base,web-browsing,ssl','','','renren',0,'no','China'),(1666,'rezgo',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1670,'ringcentral',NULL,'',4,'collaboration','voip-video','client-server','no','yes','yes','yes','yes','yes','no','no','tcp/5060-5091,5096,5099,tcp/80,443,udp/5060-5091,5096,5097,5099',0,'sip,ssl,web-browsing','','','',0,'yes','USA'),(1696,'rtmfp',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','yes','udp/dynamic',0,'','','','',0,'no','USA'),(1711,'saasu',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes',''),(1712,'saba-centra-meeting',NULL,'',4,'collaboration','internet-conferencing','client-server','yes','yes','no','yes','yes','no','no','no','tcp/443,dynamic',0,'ssl,stun,web-browsing','','','',0,'yes','USA'),(1714,'salesforce-base',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','no','yes','tcp/80,443,4309',0,'ssl','','web-browsing','salesforce',0,'yes','USA'),(1715,'salesforce-chatter',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'salesforce-base,ssl,web-browsing','','','salesforce',0,'yes','USA'),(1716,'salesforce-desk',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'google-base,ssl,web-browsing','','','',0,'yes',''),(1718,'samanage',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1719,'samsung-updates',NULL,'',1,'business-systems','software-update','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'no','USA'),(1721,'sap-jam-base',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','no','no','yes','yes','tcp/80,443',0,'','','ssl,web-browsing','sap-jam',0,'yes','USA'),(1722,'sap-jam-uploading',NULL,'',3,'business-systems','erp-crm','browser-based','no','yes','no','yes','no','no','yes','yes','tcp/443,80',0,'sap-jam-base','','ssl,web-browsing','sap-jam',0,'no','USA'),(1728,'sccp',NULL,'',2,'collaboration','voip-video','peer-to-peer','no','no','no','no','yes','no','no','yes','tcp/2000',0,'tftp','','','',0,'no','USA'),(1733,'screencast-base',NULL,'',4,'media','photo-video','browser-based','no','no','no','yes','yes','yes','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','screencast',0,'yes','USA'),(1734,'screencast-uploading',NULL,'',2,'media','photo-video','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'screencast-base,web-browsing,ssl','','','screencast',0,'no',''),(1736,'scribd-base',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','scribd',0,'no','USA'),(1737,'scribd-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','scribd',0,'no','USA'),(1740,'seamless-phenom',NULL,'',4,'general-internet','file-sharing','peer-to-peer','yes','yes','no','yes','no','yes','no','yes','tcp/dynamic',0,'web-browsing,ssl','','','',0,'no','USA'),(1741,'second-life-base',NULL,'',4,'media','gaming','client-server','yes','yes','no','no','yes','no','yes','yes','tcp/80,443,12043,12046,21002,udp/12043,13000-13050',0,'web-browsing','','','second-life',0,'no','USA'),(1742,'second-life-voice-chat',NULL,'',1,'collaboration','voip-video','client-server','no','no','no','no','no','no','no','no','udp/12000-17000,udp/3478,3479,5060,5062',0,'second-life-base,sip,web-browsing','','','second-life',0,'no','USA'),(1746,'secure-data-space-base',NULL,'',1,'business-systems','management','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','secure-data-space',0,'no',''),(1747,'secure-data-space-downloading',NULL,'',2,'business-systems','management','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'secure-data-space-base,ssl,web-browsing','','','secure-data-space',0,'yes',''),(1748,'secure-data-space-editing',NULL,'',1,'business-systems','management','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'secure-data-space-base,ssl,web-browsing','','','secure-data-space',0,'yes',''),(1749,'secure-data-space-posting',NULL,'',1,'business-systems','management','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'secure-data-space-base,ssl,web-browsing','','','secure-data-space',0,'yes',''),(1750,'secure-data-space-sharing',NULL,'',1,'business-systems','management','client-server','no','no','no','no','yes','no','no','no','tcp/80,443',0,'secure-data-space-uploading,ssl,web-browsing,secure-data-space-base','','','secure-data-space',0,'yes',''),(1751,'secure-data-space-uploading',NULL,'',2,'business-systems','management','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'secure-data-space-base,ssl,web-browsing','','','secure-data-space',0,'no',''),(1753,'securemeeting',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','no','yes','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1761,'sendgrid',NULL,'',2,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'web-browsing','','ssl','',0,'yes','USA'),(1762,'sendoid',NULL,'',2,'general-internet','file-sharing','peer-to-peer','no','yes','no','yes','no','no','yes','no','tcp/80,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1763,'sendspace',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','no','no','yes','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(1764,'sendthisfile-base',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'','','ssl,web-browsing','sendthisfile',0,'no','USA'),(1765,'sendthisfile-uploading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'sendthisfile-base','','ssl','sendthisfile',0,'no','USA'),(1767,'service-now',NULL,'',2,'business-systems','management','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1769,'sfax',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(1771,'share-p2p',NULL,'',4,'general-internet','file-sharing','peer-to-peer','yes','yes','no','yes','no','no','yes','yes','tcp/dynamic,udp/dynamic',0,'','','','',0,'no','USA'),(1774,'sharefile-base',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','sharefile',0,'yes','USA'),(1775,'sharefile-downloading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','sharefile',0,'yes',''),(1776,'sharefile-editing',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','sharefile',0,'yes',''),(1777,'sharefile-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'sharefile-base,ssl,web-browsing','','','sharefile',0,'yes','USA'),(1783,'sharepoint-online',NULL,'',3,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443,80',0,'ms-office365-base,ssl,web-browsing','','','ms-office365',0,'yes','USA'),(1785,'sharevault-base',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','no','yes','yes','no','no','tcp/443',0,'web-browsing','','ssl','sharevault',0,'yes',''),(1786,'sharevault-file-transfer',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'sharevault-base,web-browsing','','ssl','sharevault',0,'yes',''),(1792,'showmypc',NULL,'',4,'networking','remote-access','client-server','yes','no','no','yes','yes','yes','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1804,'sightspeed',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','no','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1806,'signiant-base',NULL,'',2,'general-internet','file-sharing','client-server','no','yes','no','yes','no','no','no','no','tcp/80,8080,443,49221,udp/49221-49321',0,'ssl,web-browsing','','','signiant',0,'yes','USA'),(1807,'signiant-uploading',NULL,'',3,'general-internet','file-sharing','client-server','yes','yes','no','yes','no','no','no','no','tcp/80,443,49221,udp/49221-49321',0,'','','web-browsing','signiant',0,'yes','USA'),(1808,'signnow',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(1814,'simplenote',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','no','no','no','yes','tcp/80,443',0,'google-app-engine,ssl,web-browsing,google-base','','','',0,'yes','USA'),(1815,'simplify',NULL,'',3,'media','audio-streaming','peer-to-peer','yes','yes','no','no','no','yes','no','yes','tcp/443,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1816,'simplite-msn',NULL,'',4,'collaboration','instant-messaging','peer-to-peer','yes','no','yes','yes','yes','no','no','no','tcp/80,1863',0,'ssl,web-browsing','','','',0,'no','China'),(1817,'sina-uc-base',NULL,'',3,'collaboration','instant-messaging','client-server','yes','no','no','no','yes','yes','no','yes','tcp/80,443,5222,9000,udp/dynamic',0,'google-base,web-browsing','','jabber','sina-uc',0,'no','China'),(1818,'sina-uc-audio-video',NULL,'',2,'collaboration','voip-video','client-server','no','no','no','no','yes','no','no','yes','udp/dynamic',0,'sina-uc-base,stun,google-base,web-browsing','','','sina-uc',0,'yes','China'),(1819,'sina-uc-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'sina-uc-base,web-browsing,google-base','','','sina-uc',0,'yes','China'),(1820,'sina-uc-remote-control',NULL,'',2,'networking','remote-access','client-server','yes','no','no','no','no','no','yes','yes','udp/8001,dynamic',0,'sina-uc-base,stun,vnc-base,google-base,web-browsing','','','sina-uc',0,'no','China'),(1821,'sina-uc-web-disk',NULL,'',4,'general-internet','file-sharing','client-server','yes','yes','no','yes','yes','no','no','yes','tcp/80',0,'sina-uc-base,web-browsing,google-base','','','sina-uc',0,'yes','China'),(1823,'sina-weibo-base',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','no','yes','yes','no','yes','tcp/80',0,'web-browsing','','','sina-weibo',0,'no','China'),(1824,'sina-weibo-posting',NULL,'',3,'collaboration','social-networking','browser-based','no','no','yes','no','yes','no','no','yes','tcp/80',0,'web-browsing','','','sina-weibo',0,'no','China'),(1825,'sip',NULL,'',4,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','yes','no','yes','tcp/5060,udp/5060',0,'','','','',0,'no','USA'),(1826,'sip-application',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','no','no','no','no','no','no','yes','udp/dynamic',0,'sip','','','',0,'no','USA'),(1827,'sip-message',NULL,'',1,'collaboration','instant-messaging','peer-to-peer','no','no','no','no','no','no','no','yes','udp/dynamic',0,'sip','','','',0,'no','USA'),(1828,'sip-trunk',NULL,'',3,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','no','no','yes','tcp/5060,udp/5060',0,'','','','',0,'no','USA'),(1830,'sipcli',NULL,'',3,'collaboration','voip-video','peer-to-peer','no','yes','yes','no','yes','no','no','no','udp/5060',0,'sip','','','',0,'no','USA'),(1836,'skydrive-base',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','no','no','yes','yes','tcp/443,tcp/80',0,'live-mesh-base,ssl,web-browsing','','','skydrive',0,'yes','USA'),(1837,'skydrive-uploading',NULL,'',4,'general-internet','file-sharing','client-server','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'live-mesh-base,skydrive-base,ssl,web-browsing','','','skydrive',0,'yes','USA'),(1838,'skype',NULL,'',5,'collaboration','voip-video','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'office365-consumer-access,ssl,stun,web-browsing,websocket,windows-azure-base','','','',0,'yes','USA'),(1839,'skype-probe',NULL,'',2,'collaboration','voip-video','peer-to-peer','yes','no','no','no','no','no','yes','yes','udp/dynamic',0,'','','','',0,'no','USA'),(1840,'skytap',NULL,'',2,'networking','infrastructure','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'','','ssl,web-browsing','',0,'yes','USA'),(1841,'slack-base',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing,websocket','','','slack',0,'yes','USA'),(1842,'slack-call',NULL,'',2,'collaboration','instant-messaging','browser-based','no','yes','no','no','yes','no','no','no','tcp/80,443,udp/22466',0,'slack-base,ssl,stun,web-browsing,websocket','','','slack',0,'yes',''),(1843,'slack-file-transfer',NULL,'',4,'collaboration','social-business','browser-based','no','yes','yes','yes','yes','no','no','no','tcp/443',0,'slack-base,ssl,web-browsing,websocket','','','slack',0,'yes',''),(1846,'slideshare-base',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','slideshare',0,'yes','USA'),(1847,'slideshare-uploading',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'amazon-cloud-drive-uploading,slideshare-base,amazon-cloud-drive-base,ssl,web-browsing','','ssl,web-browsing','slideshare',0,'yes','USA'),(1852,'smartsheet-base',NULL,'',1,'collaboration','social-business','browser-based','no','no','no','yes','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','smartsheet',0,'yes','USA'),(1853,'smartsheet-uploading',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','yes','no','no','no','no','tcp/80,443',0,'amazon-cloud-drive-uploading,smartsheet-base,ssl,web-browsing,amazon-cloud-drive-base','','','smartsheet',0,'yes','USA'),(1859,'snapchat',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','yes','no','no','yes','yes','tcp/80,443',0,'google-app-engine,google-base,google-cloud-storage-base','','ssl,web-browsing','',0,'no','USA'),(1871,'socialcam',NULL,'',2,'media','photo-video','client-server','no','yes','no','yes','no','no','no','yes','tcp/80,443',0,'facebook-base,ssl','','web-browsing','',0,'yes','USA'),(1875,'softros-messenger-base',NULL,'',1,'collaboration','instant-messaging','peer-to-peer','no','no','no','no','no','no','no','no','tcp/19771,udp/dynamic',0,'','','','softros-messenger',0,'no','USA'),(1876,'softros-messenger-file-transfer',NULL,'',1,'general-internet','file-sharing','peer-to-peer','no','no','no','yes','no','no','no','no','tcp/19880',0,'softros-messenger-base','','','softros-messenger',0,'no','USA'),(1883,'sopcast',NULL,'',5,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','yes','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(1887,'soribada',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/80',0,'','','','',0,'no','USA'),(1888,'sosbackup',NULL,'',4,'business-systems','storage-backup','client-server','yes','yes','no','yes','yes','no','yes','yes','tcp/80,443',0,'soap,ssl,web-browsing','','','',0,'yes','USA'),(1890,'soulseek',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/2230-2250',0,'','','','',0,'no','USA'),(1891,'soundcloud-base',NULL,'',2,'media','audio-streaming','client-server','no','yes','no','yes','no','no','no','yes','tcp/80,443',0,'amazon-cloud-drive-uploading,ssl,web-browsing,websocket,amazon-cloud-drive-base','','rtmp','soundcloud',0,'no','USA'),(1892,'soundcloud-uploading',NULL,'',3,'media','audio-streaming','client-server','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'soundcloud-base,ssl,web-browsing,amazon-cloud-drive-uploading,websocket,amazon-cloud-drive-base','','','soundcloud',0,'no','USA'),(1895,'sourceforge-base',NULL,'',2,'general-internet','file-sharing','client-server','no','no','no','no','yes','no','no','yes','tcp/80,443,9418,3690',0,'git-base,ssh,subversion-base,ssl,web-browsing','','ssl,web-browsing','sourceforge',0,'yes','USA'),(1896,'sourceforge-file-transfer',NULL,'',2,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'sourceforge-base,ssl,git-base,ssh,subversion-base,web-browsing','','web-browsing','sourceforge',0,'no','USA'),(1898,'spanning',NULL,'',2,'business-systems','storage-backup','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(1901,'spark-im-file-transfer',NULL,'',2,'collaboration','instant-messaging','peer-to-peer','no','no','no','yes','no','yes','no','no','tcp/5222,5223,7777',0,'jabber,socks,spark-im-base,ssl','','','spark-im',0,'no','USA'),(1905,'spideroak',NULL,'',3,'business-systems','storage-backup','client-server','yes','yes','no','yes','no','no','no','no','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(1910,'spotify',NULL,'',3,'media','audio-streaming','client-server','yes','yes','no','no','yes','no','no','yes','tcp/80,dynamic,udp/57621',0,'rtmp,ssl,web-browsing','','','',0,'no','Sweden'),(1912,'springcm',NULL,'',2,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1914,'sproutsocial',NULL,'',4,'collaboration','social-networking','browser-based','no','yes','yes','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(1934,'ssdp',NULL,'',1,'networking','infrastructure','peer-to-peer','no','no','no','no','no','no','no','no','tcp/1900,udp/1900',0,'','','','',0,'no','USA'),(1941,'startmail',NULL,'',2,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'','','ssl','',0,'yes',''),(1943,'stealthnet',NULL,'',4,'general-internet','file-sharing','peer-to-peer','no','yes','no','yes','yes','no','yes','yes','tcp/80,6097',0,'web-browsing','','','',0,'no','USA'),(1944,'steam',NULL,'',3,'media','gaming','client-server','no','yes','yes','no','yes','no','no','yes','tcp/80,443,27014-27050,udp/3748,4379-4380,27000-27036',0,'source-engine,web-browsing','','','',0,'no','USA'),(1949,'stocktwits-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','no','no','yes','yes','tcp/443,80',0,'','','ssl,web-browsing','stocktwits',0,'no','USA'),(1950,'stocktwits-posting',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','yes','no','no','yes','yes','tcp/443,80',0,'stocktwits-base','','ssl,web-browsing','stocktwits',0,'no','USA'),(1952,'storify-base',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','yes','no','no','tcp/80,443',0,'ssl,web-browsing','','','storify',0,'no',''),(1953,'storify-posting',NULL,'',1,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','no','tcp/80,443',0,'storify-base,ssl,web-browsing','','','storify',0,'no',''),(1969,'successfactors',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes',''),(1970,'sugar-crm',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','no','yes','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1971,'sugarsync',NULL,'',4,'general-internet','file-sharing','client-server','yes','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl','','web-browsing','',0,'yes','USA'),(1973,'sumo-logic',NULL,'',3,'business-systems','management','browser-based','no','yes','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes',''),(1978,'surveymonkey',NULL,'',2,'business-systems','marketing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'amazon-cloud-drive-uploading,google-analytics,web-browsing,amazon-cloud-drive-base,ssl','','ssl','',0,'yes',''),(1989,'syncplicity',NULL,'',3,'general-internet','file-sharing','client-server','no','yes','no','yes','yes','no','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(1999,'tableau-public',NULL,'',3,'general-internet','internet-utility','client-server','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'','','ssl,web-browsing','',0,'no','USA'),(2005,'talkbox',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','yes','no','no','no','no','tcp/dynamic',0,'web-browsing','','','',0,'yes','Hong Kong'),(2014,'teamsound',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','yes','tcp/40000,40001,udp/40000,40001,40002,40003,40004',0,'','','','',0,'no','USA'),(2015,'teamspeak',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','yes','tcp/8765,443,80,10011,30033,41144,udp/dynamic',0,'ssl,web-browsing','','','',0,'no','USA'),(2016,'teamup-calendar-base',NULL,'',4,'business-systems','general-business','browser-based','no','no','yes','yes','yes','yes','no','no','tcp/80,443',0,'ssl,web-browsing','','','teamup-calendar',0,'yes',''),(2017,'teamup-calendar-uploading',NULL,'',4,'business-systems','general-business','browser-based','no','no','yes','yes','yes','no','no','no','tcp/443',0,'teamup-calendar-base,ssl,web-browsing','','','teamup-calendar',0,'yes',''),(2018,'teamviewer-base',NULL,'',3,'networking','remote-access','client-server','no','no','no','yes','yes','yes','no','yes','tcp/80,443,5938,udp/dynamic',0,'adobe-flash-socketpolicy-server,ssl,web-browsing','','','teamviewer',0,'yes','USA'),(2019,'teamviewer-remote-control',NULL,'',2,'networking','remote-access','client-server','no','no','no','no','yes','no','no','yes','tcp/80,5938,udp/dynamic',0,'teamviewer-base,adobe-flash-socketpolicy-server,ssl,web-browsing','','','teamviewer',0,'yes','USA'),(2020,'teamviewer-sharing',NULL,'',2,'networking','remote-access','client-server','no','no','no','no','yes','no','no','yes','tcp/80,443,5938,udp/dynamic',0,'teamviewer-base,adobe-flash-socketpolicy-server,ssl,web-browsing','','','teamviewer',0,'yes','USA'),(2021,'teamviewer-web',NULL,'',2,'networking','remote-access','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'adobe-flash-socketpolicy-server,ssl,web-browsing','','','',0,'no',''),(2022,'techinline',NULL,'',4,'networking','remote-access','browser-based','yes','yes','no','no','yes','yes','yes','yes','tcp/443,tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2023,'telegram',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl','','web-browsing','',0,'no','USA'),(2024,'telenet-webmail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'ssl','','web-browsing','',0,'yes','Belgium'),(2033,'tesla',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','no','tcp/3125,udp/3125',0,'','','','',0,'no','USA'),(2036,'thecircle',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/123,udp/123',0,'','','','',0,'no','USA'),(2037,'thinkfree',NULL,'',4,'business-systems','office-programs','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2038,'thousandeyes',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(2040,'thwapr-base',NULL,'',2,'media','photo-video','client-server','no','no','no','no','yes','no','no','yes','tcp/80,60000-60010',0,'web-browsing','','','thwapr',0,'no','USA'),(2041,'thwapr-sharing',NULL,'',1,'media','photo-video','client-server','no','no','no','no','no','no','no','yes','tcp/80',0,'thwapr-base,web-browsing','','','thwapr',0,'no','USA'),(2042,'thwapr-uploading',NULL,'',4,'media','photo-video','client-server','yes','yes','no','yes','yes','no','no','yes','tcp/80',0,'thwapr-base,web-browsing','','','thwapr',0,'no','USA'),(2043,'tibbr',NULL,'',3,'collaboration','social-business','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2046,'tigertext',NULL,'',3,'collaboration','social-business','client-server','no','no','no','yes','yes','yes','no','no','tcp/443,tcp/5222',0,'ssl,web-browsing','','jabber','',0,'yes',''),(2050,'tinder',NULL,'',1,'collaboration','social-networking','client-server','no','no','no','no','yes','no','no','no','tcp/80,443,8883',0,'apple-maps,facebook-base,ssl,web-browsing','','','',0,'no','USA'),(2052,'tiscali-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','Italy'),(2057,'tokbox',NULL,'',3,'collaboration','voip-video','browser-based','yes','yes','no','no','yes','no','no','yes','tcp/80,443,udp/3478',0,'ssl,stun,web-browsing','','','',0,'yes','USA'),(2061,'torch-browser-base',NULL,'',3,'general-internet','internet-utility','browser-based','no','no','no','yes','yes','no','yes','yes','tcp/80,443',0,'bittorrent,web-browsing','','ssl','torch-browser',0,'no','USA'),(2062,'torch-browser-games',NULL,'',2,'media','gaming','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'flash,torch-browser-base,web-browsing,bittorrent','','','torch-browser',0,'no','USA'),(2063,'torch-browser-music',NULL,'',2,'media','audio-streaming','browser-based','no','no','no','no','yes','no','no','yes','tcp/80',0,'torch-browser-base,web-browsing,bittorrent','','','torch-browser',0,'no','USA'),(2065,'totodisk',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic',0,'web-browsing','','','',0,'no','Korea'),(2072,'transferbigfiles',NULL,'',5,'general-internet','file-sharing','browser-based','yes','yes','yes','yes','yes','no','no','yes','tcp/443,tcp/80',0,'web-browsing','','ssl','',0,'yes','USA'),(2073,'trello-base',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,websocket','','web-browsing','trello',0,'yes',''),(2074,'trello-uploading',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/443,80',0,'ssl,trello-base,web-browsing,websocket','','','trello',0,'yes',''),(2079,'trillian',NULL,'',3,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','no','no','yes','tcp/3158,tcp/dynamic,udp/dynamic',0,'','','ssl,stun,web-browsing','',0,'yes','USA'),(2080,'trinoo',NULL,'',5,'general-internet','internet-utility','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/27665,udp/27444,31335',0,'','','','',0,'no','USA'),(2082,'trueshare',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','yes','yes','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2088,'tubes',NULL,'',4,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','no','no','yes','no','tcp/80,443',0,'web-browsing','','','',0,'no','USA'),(2090,'tudou-speedup',NULL,'',4,'media','photo-video','peer-to-peer','no','yes','no','yes','yes','no','yes','yes','tcp/80,8000,10778,udp/dynamic',0,'web-browsing','','','',0,'no','China'),(2092,'tumblr-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl','','web-browsing','tumblr',0,'no','USA'),(2093,'tumblr-posting',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'tumblr-base,ssl','','web-browsing','tumblr',0,'no','USA'),(2099,'tvants',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(2104,'twilio',NULL,'',2,'collaboration','voip-video','client-server','no','yes','no','no','yes','no','no','yes','tcp/80,443,1935,3478,udp/3478',0,'rtcp,rtp-base,stun,websocket','','rtmp,ssl,web-browsing','',0,'yes','USA'),(2107,'twitter-base',NULL,'',2,'collaboration','social-networking','browser-based','no','no','yes','no','no','no','no','yes','tcp/80,443',0,'ssl','','web-browsing','twitter',0,'no','USA'),(2108,'twitter-posting',NULL,'',4,'collaboration','social-networking','browser-based','yes','no','yes','no','yes','no','no','yes','tcp/80,443',0,'twitter-base,ssl','','','twitter',0,'no','USA'),(2112,'uberconference',NULL,'',1,'collaboration','internet-conferencing','browser-based','no','no','no','yes','no','no','no','no','tcp/80,443',0,'boxnet-base,evernote-base,google-base,rtcp,rtp-base,stun,websocket,ssl,web-browsing','','ssl,web-browsing','',0,'yes','USA'),(2115,'uc-yun-base',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','no','yes','yes','no','no','tcp/80,443',0,'ssl,web-browsing','','','uc-yun',0,'yes',''),(2116,'uc-yun-downloading',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,uc-yun-base,web-browsing','','','uc-yun',0,'yes',''),(2117,'uc-yun-uploading',NULL,'',3,'general-internet','file-sharing','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,uc-yun-base,web-browsing','','','uc-yun',0,'yes',''),(2126,'unknown-p2p',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','udp/dynamic',0,'','','','',0,'no','USA'),(2133,'uploadmirrors',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','yes','no','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2134,'upnp',NULL,'',2,'networking','infrastructure','peer-to-peer','no','no','no','no','yes','yes','no','no','tcp/2869,udp/1900',0,'web-browsing','','','',0,'no','USA'),(2141,'uusee',NULL,'',4,'media','photo-video','peer-to-peer','yes','yes','no','yes','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(2142,'vagaa',NULL,'',4,'general-internet','file-sharing','peer-to-peer','yes','yes','no','yes','no','no','yes','yes','tcp/1000-4500,udp/2000-2200',0,'bittorrent,emule,web-browsing','','','',0,'no','China'),(2143,'vagrant',NULL,'',2,'business-systems','software-development','client-server','no','no','no','no','yes','no','yes','no','tcp/80,443',0,'','','ssl,web-browsing','',0,'yes','USA'),(2144,'vakaka',NULL,'',3,'media','photo-video','peer-to-peer','yes','yes','no','no','yes','no','yes','no','tcp/80',0,'web-browsing','','','',0,'no','USA'),(2148,'ventrilo',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','yes','tcp/3784,udp/43784',0,'','','','',0,'no','USA'),(2153,'via3',NULL,'',2,'collaboration','internet-conferencing','client-server','no','yes','no','yes','no','no','no','no','tcp/80,443,5061,5004,udp/5004',0,'','','ssl,web-browsing','',0,'yes','USA'),(2155,'viber-base',NULL,'',1,'collaboration','voip-video','client-server','no','no','no','no','no','no','no','no','tcp/dynamic,udp/dynamic',0,'ssl,web-browsing','','','viber',0,'yes','USA'),(2156,'viber-voice',NULL,'',1,'collaboration','voip-video','client-server','yes','no','no','no','no','no','no','no','tcp/443,udp/dynamic',0,'ssl,viber-base,web-browsing','','','viber',0,'yes','USA'),(2159,'vidyo',NULL,'',1,'collaboration','internet-conferencing','client-server','no','yes','no','no','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'rtcp,rtp-base,ssl,stun','','','',0,'yes','USA'),(2160,'vimeo-base',NULL,'',4,'media','photo-video','browser-based','yes','yes','no','no','yes','yes','no','yes','tcp/80,443,8080',0,'ssl,web-browsing','','','vimeo',0,'no','USA'),(2161,'vimeo-uploading',NULL,'',3,'media','photo-video','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/80,443,8080',0,'ssl,vimeo-base,web-browsing','','web-browsing','vimeo',0,'no','USA'),(2162,'vine-base',NULL,'',1,'collaboration','social-networking','client-server','no','no','no','no','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','vine',0,'no','USA'),(2163,'vine-posting',NULL,'',2,'collaboration','social-networking','client-server','no','no','no','yes','no','no','no','yes','tcp/443',0,'ssl,vine-base,web-browsing','','','vine',0,'no','USA'),(2166,'virustotal-base',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','yes','no','no','no','yes','tcp/80,443',0,'google-app-engine,ssl,web-browsing,google-base','','','virustotal',0,'no','USA'),(2167,'virustotal-api-uploading',NULL,'',3,'general-internet','internet-utility','client-server','no','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,virustotal-base,web-browsing,google-app-engine,google-base','','','virustotal',0,'no','USA'),(2168,'virustotal-web-uploading',NULL,'',3,'general-internet','internet-utility','browser-based','no','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,virustotal-base,web-browsing,google-app-engine,google-base','','','virustotal',0,'no','USA'),(2170,'vkontakte-base',NULL,'',4,'collaboration','social-networking','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'http-audio,web-browsing','','ssl,web-browsing','vkontakte',0,'no','Russia'),(2171,'vkontakte-chat',NULL,'',3,'collaboration','instant-messaging','browser-based','yes','no','no','no','yes','no','no','yes','tcp/80,443',0,'vkontakte-base,web-browsing,http-audio','','http,ssl','vkontakte',0,'no','Russia'),(2172,'vkontakte-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'vkontakte-base,http-audio,web-browsing','','ssl,web-browsing','vkontakte',0,'yes','Russia'),(2185,'vnn',NULL,'',4,'networking','encrypted-tunnel','peer-to-peer','yes','no','no','yes','yes','yes','yes','no','tcp/dynamic,udp/dynamic',0,'web-browsing','','','',0,'no','USA'),(2186,'voddler',NULL,'',1,'media','photo-video','peer-to-peer','no','yes','no','no','no','no','no','no','tcp/dynamic',0,'ssl,web-browsing','','','',0,'no','Sweden'),(2195,'vyew',NULL,'',4,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','no','yes','yes','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2202,'warez-p2p',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/32285,6000,6346-6351,udp/6346-6351',0,'web-browsing','','','',0,'no','USA'),(2204,'watchdox',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','yes','no','no','no','no','tcp/443,80',0,'','','ssl,web-browsing','',0,'yes','USA'),(2210,'weather-desktop',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'web-browsing','','','',0,'no','USA'),(2213,'web-de-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2215,'webalo',NULL,'',2,'business-systems','software-development','browser-based','no','no','no','yes','yes','no','no','no','tcp/4812,tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(2218,'webex-base',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','no','no','yes','no','yes','no','yes','tcp/443,80,1270,udp/8070,8090,9000',0,'ssl,web-browsing','','','webex',0,'yes','USA'),(2219,'webex-chat',NULL,'',2,'collaboration','instant-messaging','client-server','yes','no','no','no','no','no','no','yes','tcp/443',0,'ssl,web-browsing,webex-base','','','webex',0,'no','USA'),(2220,'webex-connect',NULL,'',1,'collaboration','instant-messaging','client-server','no','yes','no','no','no','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing,webex-base','','','',0,'yes','USA'),(2221,'webex-desktop-sharing',NULL,'',3,'collaboration','internet-conferencing','client-server','yes','yes','no','no','no','yes','yes','yes','tcp/443',0,'ssl,web-browsing,webex-base','','','webex',0,'yes','USA'),(2222,'webex-file-sharing',NULL,'',3,'general-internet','file-sharing','client-server','yes','yes','no','yes','no','no','no','yes','tcp/443',0,'ssl,web-browsing,webex-base,webex-desktop-sharing','','','webex',0,'yes','USA'),(2224,'webex-whiteboard',NULL,'',2,'collaboration','internet-conferencing','client-server','yes','no','no','no','no','no','no','yes','tcp/443',0,'ssl,web-browsing,webex-base','','','webex',0,'no','USA'),(2225,'webhard',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','Korea'),(2233,'wechat-base',NULL,'',2,'collaboration','instant-messaging','client-server','no','no','no','no','yes','no','no','yes','tcp/80,8080,443,5000,12121,udp/dynamic',0,'ssl,web-browsing','','','wechat',0,'no','China'),(2234,'wechat-audio-video',NULL,'',1,'collaboration','voip-video','client-server','no','yes','no','no','no','no','no','no','udp/dynamic',0,'wechat-base,ssl,web-browsing','','','wechat',0,'no',''),(2235,'wechat-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/80,8080,443',0,'ssl,wechat-base,web-browsing','','','wechat',0,'no','USA'),(2236,'wechat-video',NULL,'',1,'collaboration','voip-video','peer-to-peer','no','yes','no','no','no','no','no','no','udp/dynamic',0,'wechat-base,ssl,web-browsing','','','',0,'no','USA'),(2237,'weiyun-base',NULL,'',2,'general-internet','file-sharing','client-server','no','yes','no','yes','no','no','no','no','tcp/dynamic',0,'qq-base,ssl,web-browsing','','','weiyun',0,'yes','USA'),(2238,'weiyun-file-transfer',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','yes','no','no','no','no','tcp/80,8080',0,'qq-base,weiyun-base,ssl,web-browsing','','','weiyun',0,'yes','USA'),(2241,'wetransfer',NULL,'',3,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'amazon-cloud-drive-uploading,ssl,web-browsing,amazon-cloud-drive-base','','','',0,'yes','USA'),(2242,'whatsapp-base',NULL,'',1,'collaboration','instant-messaging','client-server','no','no','no','no','no','no','no','no','tcp/5222,5223,tcp/80,443',0,'','','ssl,web-browsing','whatsapp',0,'no','USA'),(2243,'whatsapp-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','no','yes','tcp/443',0,'ssl,whatsapp-base','','web-browsing','whatsapp',0,'no','USA'),(2244,'whatsapp-voice',NULL,'',1,'collaboration','voip-video','client-server','no','no','no','no','no','no','no','no','udp/dynamic',0,'rtcp,stun,whatsapp-base','','','whatsapp',0,'no','USA'),(2255,'windows-azure-base',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','no','no','no','yes','tcp/80,443,8443',0,'ssl,web-browsing','','','windows-azure',0,'yes','USA'),(2256,'windows-azure-service-updates',NULL,'',1,'business-systems','general-business','client-server','no','no','no','no','no','no','no','yes','tcp/9352',0,'','','','windows-azure',0,'no','USA'),(2257,'windows-azure-uploading',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'windows-azure-base,ssl,web-browsing','','','windows-azure',0,'no','USA'),(2259,'windows-push-notifications',NULL,'',1,'general-internet','internet-utility','client-server','no','no','no','no','no','no','no','yes','tcp/443',0,'ssl','','','',0,'no','USA'),(2262,'winmx',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/6346-6351,6881-6999,4661,4662,4671,udp/6346-6351,4665,4672',0,'','','','',0,'no','USA'),(2263,'winny',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','no','no','yes','yes','tcp/dynamic',0,'','','','',0,'no','Japan'),(2266,'wiredrive',NULL,'',1,'general-internet','file-sharing','browser-based','no','no','no','yes','no','no','no','no','tcp/443',0,'','','ssl','',0,'yes','USA'),(2273,'workday',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','no','yes','no','no','no','tcp/443',0,'ssl','','','',0,'yes','USA'),(2275,'wrike',NULL,'',2,'business-systems','management','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(2279,'wufoo',NULL,'',2,'business-systems','marketing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(2285,'xbox-live',NULL,'',3,'media','gaming','client-server','no','yes','no','no','yes','yes','no','yes','tcp/80,443,3074,udp/88,3074',0,'ike,ipsec-esp-udp,kerberos,ssl,teredo,web-browsing','','','',0,'no','USA'),(2288,'xero',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/443',0,'web-browsing','','ssl','',0,'yes','USA'),(2291,'xing',NULL,'',3,'collaboration','social-networking','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'no','USA'),(2297,'xunlei',NULL,'',5,'general-internet','file-sharing','peer-to-peer','yes','yes','yes','yes','yes','no','yes','yes','tcp/dynamic,udp/dynamic',0,'bittorrent,emule,web-browsing','','','',0,'no','China'),(2298,'xunlei-kankan',NULL,'',2,'media','photo-video','peer-to-peer','no','yes','no','yes','no','no','no','yes','tcp/80,8080,udp/dynamic',0,'web-browsing,xunlei,bittorrent,emule','','','',0,'no','China'),(2301,'yahoo-box',NULL,'',1,'general-internet','file-sharing','client-server','no','no','no','yes','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','Japan'),(2302,'yahoo-calendar',NULL,'',1,'business-systems','office-programs','browser-based','no','no','no','no','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2304,'yahoo-file-transfer',NULL,'',4,'general-internet','file-sharing','peer-to-peer','no','no','yes','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing,yahoo-im-base','','','yahoo-im',0,'no','USA'),(2306,'yahoo-im-base',NULL,'',4,'collaboration','instant-messaging','client-server','yes','no','yes','no','yes','no','no','yes','tcp/443,80,5050,5101',0,'ssl,web-browsing','','','yahoo-im',0,'no','USA'),(2307,'yahoo-mail',NULL,'',3,'collaboration','email','browser-based','no','no','yes','yes','no','no','no','yes','tcp/443,143,80,993,465',0,'ssl,web-browsing','','','',0,'yes','USA'),(2308,'yahoo-notepad',NULL,'',2,'general-internet','internet-utility','browser-based','no','no','no','no','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2310,'yahoo-voice',NULL,'',4,'collaboration','voip-video','peer-to-peer','yes','no','yes','no','yes','no','no','yes','tcp/5001',0,'ssl,stun,web-browsing','','','yahoo-im',0,'no','USA'),(2312,'yahoo-webcam',NULL,'',2,'collaboration','voip-video','peer-to-peer','no','yes','no','no','yes','no','no','yes','tcp/5100',0,'','','','yahoo-im',0,'no','USA'),(2314,'yammer',NULL,'',3,'collaboration','social-networking','client-server','yes','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2315,'yandex-disk',NULL,'',3,'general-internet','file-sharing','client-server','yes','no','no','yes','no','no','no','yes','tcp/80,443',0,'ssl,web-browsing,yandex-mail','','','',0,'yes','Russia'),(2316,'yandex-mail',NULL,'',4,'collaboration','email','browser-based','no','no','yes','yes','yes','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2320,'yodlee',NULL,'',2,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(2322,'yoomba',NULL,'',4,'collaboration','voip-video','peer-to-peer','yes','no','no','yes','yes','no','no','yes','tcp/443,80,udp/dynamic',0,'jabber,sip,ssl,web-browsing','','','',0,'no','USA'),(2325,'youku-base',NULL,'',5,'media','photo-video','browser-based','yes','yes','yes','yes','yes','yes','yes','yes','tcp/80',0,'ssl,web-browsing','','','youku',0,'no','USA'),(2326,'youku-uploading',NULL,'',3,'media','photo-video','browser-based','no','yes','no','yes','yes','no','no','no','tcp/80',0,'web-browsing,youku-base,ssl','','','youku',0,'no','USA'),(2331,'yousendit-base',NULL,'',4,'general-internet','file-sharing','browser-based','yes','yes','no','yes','yes','no','yes','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','yousendit',0,'no','USA'),(2332,'yousendit-uploading',NULL,'',4,'general-internet','file-sharing','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','yousendit',0,'no','USA'),(2333,'youtube-base',NULL,'',4,'media','photo-video','browser-based','yes','yes','yes','no','yes','no','no','yes','tcp/80,443',0,'google-base','','','youtube',0,'no','USA'),(2334,'youtube-posting',NULL,'',3,'collaboration','web-posting','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'google-base,youtube-base','','','youtube',0,'no','USA'),(2335,'youtube-safety-mode',NULL,'',4,'media','photo-video','browser-based','yes','yes','yes','no','yes','no','no','yes','tcp/80',0,'google-base,youtube-base','','','youtube',0,'no','USA'),(2336,'youtube-uploading',NULL,'',4,'media','photo-video','browser-based','yes','yes','no','yes','yes','no','no','yes','tcp/80,443',0,'google-base,youtube-base','','','youtube',0,'no','USA'),(2338,'yugma',NULL,'',3,'collaboration','internet-conferencing','browser-based','yes','no','no','yes','no','no','no','yes','tcp/443,80',0,'ssl,web-browsing','','','',0,'yes','USA'),(2340,'yunpan',NULL,'',3,'general-internet','internet-utility','client-server','no','no','no','yes','yes','no','yes','yes','tcp/80,443,5287',0,'ssl,web-browsing','','','',0,'yes','USA'),(2341,'yunpan360-base',NULL,'',5,'general-internet','internet-utility','client-server','no','no','yes','yes','yes','yes','yes','yes','tcp/80,443',0,'ssl,web-browsing','','','yunpan360',0,'yes','USA'),(2342,'yunpan360-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','yes','yes','tcp/80,443',0,'ssl,web-browsing,yunpan360-base','','','yunpan360',0,'yes','USA'),(2343,'yuuguu',NULL,'',2,'collaboration','internet-conferencing','client-server','yes','yes','no','no','no','yes','no','no','tcp/443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2344,'yy-voice-base',NULL,'',3,'collaboration','instant-messaging','client-server','yes','yes','no','no','yes','no','no','yes','tcp/dynamic,udp/dynamic',0,'web-browsing','','','yy-voice',0,'no','China'),(2345,'yy-voice-file-transfer',NULL,'',3,'general-internet','file-sharing','client-server','yes','yes','no','yes','no','no','no','yes','tcp/dynamic,udp/dynamic',0,'yy-voice-base,web-browsing','','','yy-voice',0,'yes','China'),(2346,'yy-voice-games',NULL,'',3,'media','gaming','client-server','yes','no','no','no','yes','no','no','yes','tcp/dynamic',0,'web-browsing,yy-voice-base','','','yy-voice',0,'no','China'),(2348,'zalo-base',NULL,'',3,'collaboration','instant-messaging','client-server','no','no','no','yes','yes','no','no','yes','tcp/dynamic',0,'ssl,web-browsing','','','zalo',0,'no',''),(2349,'zalo-audio-video',NULL,'',2,'collaboration','voip-video','client-server','no','yes','no','no','yes','no','no','no','udp/dynamic',0,'','','','zalo',0,'no',''),(2350,'zamzar',NULL,'',4,'general-internet','internet-utility','browser-based','yes','yes','no','yes','yes','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2352,'zas-communicator',NULL,'',2,'collaboration','instant-messaging','peer-to-peer','no','yes','no','yes','no','no','no','yes','udp/31265',0,'','','','',0,'no','USA'),(2354,'zello',NULL,'',3,'collaboration','social-networking','peer-to-peer','yes','no','no','no','yes','no','yes','yes','tcp/443,80,28225,udp/dynamic',0,'web-browsing','','ssl','',0,'no','USA'),(2357,'zendesk',NULL,'',3,'business-systems','general-business','browser-based','no','no','no','yes','yes','no','no','yes','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes','USA'),(2358,'zenefits',NULL,'',1,'business-systems','general-business','browser-based','no','no','no','yes','no','no','no','no','tcp/80,443',0,'ssl,web-browsing','','','',0,'yes',''),(2360,'zettahost-base',NULL,'',3,'general-internet','file-sharing','client-server','no','no','no','yes','yes','no','yes','yes','tcp/80,182',0,'','','web-browsing','zettahost',0,'no','USA'),(2361,'zettahost-uploading',NULL,'',3,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','yes','yes','tcp/80',0,'zettahost-base','','','zettahost',0,'no','USA'),(2362,'zimbra',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','yes','no','yes','tcp/80,443',0,'web-browsing','','','',0,'yes','USA'),(2363,'zippyshare',NULL,'',2,'general-internet','file-sharing','browser-based','no','no','no','yes','yes','no','no','no','tcp/80',0,'','','web-browsing','',0,'yes',''),(2365,'zoho-crm',NULL,'',2,'business-systems','erp-crm','browser-based','no','no','no','yes','yes','no','no','no','tcp/80,tcp/dynamic',0,'ssl','','web-browsing','',0,'yes','USA'),(2366,'zoho-db',NULL,'',1,'business-systems','database','network-protocol','no','no','no','no','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2367,'zoho-im',NULL,'',4,'collaboration','instant-messaging','browser-based','yes','no','no','yes','yes','no','no','yes','tcp/80',0,'ssl,web-browsing','','','',0,'yes','USA'),(2368,'zoho-mail',NULL,'',3,'collaboration','email','browser-based','no','no','no','yes','yes','no','no','yes','tcp/443,tcp/80',0,'ssl,web-browsing','','','',0,'yes','USA'),(2369,'zoho-meeting',NULL,'',2,'collaboration','internet-conferencing','browser-based','yes','no','no','no','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2371,'zoho-people',NULL,'',1,'business-systems','erp-crm','browser-based','no','no','no','no','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2372,'zoho-planner',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2373,'zoho-share',NULL,'',3,'business-systems','office-programs','browser-based','yes','no','no','yes','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2374,'zoho-sheet',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2375,'zoho-show',NULL,'',3,'business-systems','office-programs','browser-based','yes','no','no','yes','no','no','no','yes','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2376,'zoho-wiki',NULL,'',2,'collaboration','web-posting','browser-based','no','no','no','yes','no','no','yes','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2377,'zoho-writer',NULL,'',2,'business-systems','office-programs','browser-based','no','no','no','yes','yes','no','no','no','tcp/80',0,'web-browsing','','','',0,'yes','USA'),(2378,'zoom',NULL,'',1,'collaboration','internet-conferencing','client-server','no','yes','no','no','no','no','no','no','tcp/80,443,3478,3479,8801,8802,udp/dynamic',0,'ssl,stun','','web-browsing','',0,'yes','USA'),(2392,'amazon-cloud-drive',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'ssl,web-browsing,ssl,web-browsing','amazon-cloud-drive-base,amazon-cloud-drive-uploading','','',0,'no',NULL),(2430,'google-calendar',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,google-base,google-base','google-calendar-base,google-calendar-enterprise,google-calendar-posting','','',0,'no',NULL),(2431,'google-cloud-storage',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,google-base','google-cloud-storage-base,google-cloud-storage-upload','','',0,'no',NULL),(2432,'google-docs',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,google-base,google-base,google-base,google-base','google-docs-base,google-docs-enterprise,google-docs-editing,google-docs-uploading,google-docs-downloading,google-docs-sharing,google-docs-posting','','',0,'no',NULL),(2433,'google-hangouts',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,google-plus-base,jabber,ssl,rtcp,rtp-base,stun,vidyo,google-base,google-plus-base,jabber,ssl,rtcp,rtp-base,stun,vidyo,google-base,google-plus-base,jabber,ssl,rtcp,rtp-base,stun,vidyo','google-hangouts-base,google-hangouts-chat,google-hangouts-audio-video','','',0,'no',NULL),(2434,'google-plus',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,jabber,ssl,google-base,jabber,ssl','google-plus-base,google-plus-posting','','',0,'no',NULL),(2435,'google-spaces',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,google-base','google-spaces-base,google-spaces-posting','','',0,'no',NULL),(2436,'google-talk',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,stun,google-base,stun','google-talk-base,gtalk-file-transfer,gtalk-voice','','',0,'no',NULL),(2437,'google-translate',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base,google-base,google-base','google-translate-base,google-translate-auto,google-translate-manual','','',0,'no',NULL),(2438,'google-video',NULL,'',0,'','','','no','no','no','no','no','no','no','no','',0,'google-base','google-video-base,google-video-enterprise','','',0,'no',NULL);
/*!40000 ALTER TABLE `cloud_default_apps` ENABLE KEYS */;
UNLOCK TABLES;


# CREATE TABLE `custom_url_category` (
#   `id` INT(11) NOT NULL AUTO_INCREMENT,
#   `name` VARCHAR(255) NOT NULL,
#   `name_ext` VARCHAR(255) NOT NULL,
#   `xml` TEXT NOT NULL,
#   `type` VARCHAR(45) NOT NULL,
#   `vsys` VARCHAR(31) NOT NULL,
#   `devicegroup` VARCHAR(255) NOT NULL,
#   `modified` INT(1) NOT NULL DEFAULT 1,
#   `dummy` INT(1) NOT NULL DEFAULT 0,
#   `checkit` INT(1) NOT NULL DEFAULT 0,
#   `disable_override` VARCHAR(3) NOT NULL,
#   `source` INT(11) NOT NULL,
#   PRIMARY KEY (`id`),
#   UNIQUE INDEX `id_UNIQUE` (`id` ASC));

-- DROP TABLE IF EXISTS `tools_rename`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tools_rename` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `lid` int(11) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `reverse` varchar(1024) NOT NULL,
  `ipaddress` varchar(255) NOT NULL,
  `extra` varchar(1024) NOT NULL,
  `user` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `vsys` varchar(31) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;


CREATE TABLE `topology_zones` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `source` INT NOT NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `topology_networks` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(255) NOT NULL,
    `ipaddress` VARCHAR(45) NOT NULL,
    `cidr` INT NOT NULL,
    `source` INT NULL,
    PRIMARY KEY (`id`));

CREATE TABLE `topology_rules` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `connector` INT NOT NULL,
    `parent_rule_id` INT NOT NULL DEFAULT 0,
    `operator` VARCHAR(45) NOT NULL DEFAULT 'AND',
    `field1_table` VARCHAR(255) NOT NULL,
    `field1_lid` INT NOT NULL,
    `field2_table` VARCHAR(255) NULL,
    `field2_lid` INT NULL,
    PRIMARY KEY (`id`));

CREATE TABLE `ML_RuleEnrichment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `RuleID` varchar(45) NOT NULL,
  `RuleName` varchar(255) NOT NULL,
  `Application` mediumtext,
  `ServicesTCP` mediumtext,
  `ServicesUDP` mediumtext,
  `Sources` mediumtext,
  `SourcesRegions` mediumtext,
  `SourcesZones` MEDIUMTEXT NULL ,
  `Users` mediumtext,
  `Destinations` mediumtext,
  `DestinationRegions` mediumtext,
  `DestinationZones` MEDIUMTEXT NULL,
  `timestamp` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
