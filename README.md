# IPsec Watch

Aplicativo Windows leve para visualizar Security Associations IPsec ativas e gerar tráfego periódico para manter túneis sob demanda conectados.

## Executar

O executável pronto fica em `dist\IpsecWatch.exe`. Ele solicita elevação de administrador porque a leitura das SAs IPsec pode exigir esse nível de acesso.

Na primeira execução:

1. Abra **Monitores / keepalive** e clique em **Adicionar**.
2. Informe um IP/hostname interno e a porta TCP de um serviço que exista atrás do túnel.
3. O socket usa sempre `10.69.69.1` como IP de origem.
4. Opcionalmente informe o endpoint público do peer para correlacionar esse monitor com uma SA.
5. Use um intervalo de 20 a 60 segundos como ponto de partida.

Minimizar ou fechar mantém o programa na bandeja. Para encerrar, clique com o botão direito no ícone e escolha **Sair**.

A opção **Iniciar com o Windows** cria uma tarefa agendada para o usuário atual com privilégios elevados; isso permite consultar as SAs automaticamente após o logon.

As configurações ficam em `%APPDATA%\IpsecWatch\settings.xml`. Nenhuma credencial é armazenada.

## Compilar

No PowerShell, a partir desta pasta:

```powershell
.\build.ps1
```

O build usa o compilador do .NET Framework já incluído no Windows e não exige Visual Studio nem .NET SDK.

## Como funciona

- Consulta `Get-NetIPsecMainModeSA` e `Get-NetIPsecQuickModeSA` a cada 10 segundos.
- Por padrão abre uma conexão TCP curta (`tcping`) vinculada ao IP local fixo `10.69.69.1`. Destino, porta e intervalo são configuráveis por monitor.
- ICMP continua disponível como alternativa e também usa a origem configurada.
- Exibe separadamente a resposta do host e o estado da SA IPsec. Um host pode bloquear ICMP mesmo com o túnel ativo.
- Não modifica políticas IPsec, não reinicia serviços e não conecta usando credenciais.

Compatível com Windows 10/11 e Windows Server que tenham o módulo `NetSecurity`.
