-- Banco de dados: `ion_auth`
--

-- --------------------------------------------------------

--
-- Estrutura da tabela `device_authorization`
--

CREATE TABLE `device_authorization` (
  `id` int(11) NOT NULL,
  `user_agent` varchar(100) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `login` varchar(100) NOT NULL,
  `device_selector` varchar(255) DEFAULT NULL,
  `device_code` varchar(255) DEFAULT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  `time` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
--
-- Índices para tabelas despejadas
--

--
-- Índices para tabela `device_authorization`
--
ALTER TABLE `device_authorization`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `allowed_selector_UNIQUE` (`device_selector`);

--
-- AUTO_INCREMENT de tabela `device_authorization`
--
ALTER TABLE `device_authorization`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=0;
COMMIT;
