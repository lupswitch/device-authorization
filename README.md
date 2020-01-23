# Device authorization

```sql 
DROP TABLE IF EXISTS `device_authorization`;

#
# Table structure for table 'device_authorization'
#

CREATE TABLE `device_authorization` (
  `id` int(11) NOT NULL,
  `user_agent` varchar(100) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `login` varchar(100) NOT NULL,
  `allowed_selector` varchar(255) DEFAULT NULL,
  `allowed_code` varchar(255) DEFAULT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `device_authorization`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `allowed_selector_UNIQUE` (`allowed_selector`);

ALTER TABLE `device_authorization`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
```
