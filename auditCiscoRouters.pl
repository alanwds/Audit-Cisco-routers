#!/usr/bin/perl

#Autor: Alan Santos - alanwds@gmail.com
#Observacao: Executar com usuario comum, nao com root
#Observacao 2: Necessário fazer um refactoring, colocando os parametros de segurança em variáveis no início do script e/ou usar arquivo externo com os parametros a serem observados.

#Script para coletar informacoes em equipamentos cisco e comparar com os parametros de segurança setados(compliance check).
#Cada prametro sera checado e se estiver aderente aos paramêtros, será setado como "conforme". Caso não, será setado como "Não conforme".
#O script gera uma saída em um arquivo check_router.log e por syslog

#Script to get info from cisco routers and compair with security params (Compliance check).
#Each param will be checked and, if was ok it will be setted as "Conforme", else, will be setted as "Nao conforme".
#The script write the output in a local log file (check_router.log) and by syslog

#Dependencias:
#Net::Telnet -> http://search.cpan.org/~jrogers/Net-Telnet-3.03/lib/Net/Telnet.pm
#Net::Telnet::Cisco -> http://search.cpan.org/~joshua/Net-Telnet-Cisco-1.10/Cisco.pm
#Try:tiny -> http://search.cpan.org/~doy/Try-Tiny-0.11/lib/Try/Tiny.pm
#Net::Syslog-> http://search.cpan.org/~lhoward/Net-Syslog-0.04/Syslog.pm

use warnings;
use strict; 
use Socket;

#Classe para conexao com syslog server
use Net::Syslog;

#Classe para tratar erros
use Try::Tiny;

#Classe para conexoes cisco via SSH
use Net::SSH::Perl;

#Classe para conexoes cisco via TELNET
#use Net::Telnet::Cisco;

#Classe para tratamento de parametros
use Getopt::Std;

#Inicia vetor para armazenamento e validacao de parametros 
my %args = ();

#Associa os argumentos ao vetor criado
getopts(":h:p:c:F:", \%args);

#Verifica se os parametros foram passados corretamente, se nao foram passados, sera exibido o help

#Testa se o parametro -h e -F foram passados de forma simultanea. Caso sim, o help deve ser utilizado
	if (($args{h}) && ($args{F}))
	{
		&exibeHelp;
	}

#Testa se os parametros -h e -F nao existem e se os parametros -p ou -c tambem nao existem 

	if (((!$args{h}) && (!$args{F})) || (!$args{c}))
	{
		&exibeHelp;
	}

#Se o parametro ip foi passado, ele ira validar o IP
	if ($args{h})
	{
	#Testa se o IP e valido ou nao
	&validaIP($args{h});
	}

#Valida o protocolo recebido como parametro. Se nao for telnet, ssh ou any, o help sera exibido 
	if ($args{p}){
		if (($args{p} ne 'telnet') && ($args{p} ne 'ssh') && ($args{p} ne 'any'))
		{
			&exibeHelp;
		}
	}

#Se for any, ira chamar a funcao para testar a conexao na porta 22 e 23. Conforme o retorno da funcao, ele ira definir se o protocolo e telnet ou ssh

	if ($args{p}){
		if ($args{p} eq 'any')
		{
			my $resultado = &testaProtocolo($args{h}); 
			if ($resultado eq '1')
			{
				$args{p} = 'telnet';
			} else {
				$args{p} = 'ssh';
			}	
		
		}
	}

#Se for arquivo e a porta nao

#Inicia o relatorio com o horario atual e os argumentos passados na inicializacao do script
&relatorio(`date +"%b %d %R:%S"`);
&relatorio("host," . "Conexao," . $args{c} . "\n");

#Verifica quais pontos devem ser testados e adiciona no array @comandos

#Trata o parametro -c / $args{c} e transforma em um array chamado @comandos
our @comandos = &parseParametro($args{c});

#Declara o array Global @comandosRouter;
our @comandosRouter = '';

#Declara o array Global @listaHosts para armazenar os hosts do arquivo passado como parametro no script
our @listaHosts;

#Declara o array Global @listaProtocolos para armazenar os protocolos dos hosts existentes no arquivo passado como parametro no script
our @listaPortas = '';

#Configuracao do syslog server
our $syslogServer = 'ip_to_syslog_server';
our $facility = 'user';
our $logLevel = 'notice';

#Lista de IPs para checagem
#Ips de acesso ao equipamento
our $ipsToAclOfAccess = 'ip_trust1|ip_trust2';

#ips com permissao para consulta SNMP
our $ipsToSnmpAccess = 'ip_snmp_trust1|ip_snmp_trust1';

#SNMP communities
out $snmpCommunities = 'snmp_communit_1|snmp_communit_2';

#Inicio das funcoes

sub testaPorta{

	my $porta = $_[0];

	if($porta =~ /23/)
	{
		return 'telnet';
	}else{
		return 'ssh';
	}

}


sub abreArquivo{

	my $file = $_[0];
	my @data;
	my @array = '';
	open(DATA, $file) || die "Nao foi possivel abrir o arquivo $file: $!\n";

	#Faz a leitura de todas as linhas do arquivo e trata a saida para armazenar nos arrays globais @listaHosts e @listaPortas
	while (<DATA>) {
		#Faz o split usando como demilitador o caracter ":"
		@array = split(/:/,$_);

		#Remove quebra de linhas sobressalentes
		chomp($array[0]);

		#Armazena os resultados relativos aos hosts no array global @listaHosts
		push(@listaHosts, $array[0] . "\n");

		#Testa se existe valor na variavel $array[1]
		#Se nao existir, chamara a funcao para testar qual porta esta aberta 
		if(!$array[1])
		{
			$array[1] = &testaProtocolo($array[0]);
			if($array[1] eq '1'){
				$array[1] = '23';
			}else{
				$array[1] = '22';
			}
		}
	
		#Armazena os resultados relativos as portas no array global @listaPortas
		push(@listaPortas, $array[1]);
	}	
}

sub parseParametro{
	my $parametro = $_[0];
	my @array = split(/,/, $parametro);
	return @array;
}

sub LOG{

        #Armazena a data e hora em uma variavel
        my $now = `date +"%b %d %R:%S"`;

        #remove a quebra de linha da data/hora
        chomp($now);

        #Recebe a string como parametro
        my ($logitem) = @_;

        #Adiciona a data/hora, espaco e a quebra de linha na linha
        $logitem = $now . " " . $logitem."\n";

        #Abre o arquivo de LOG
        open LOG, ">>check_router.log" or die $!;

        #Armazena a strings recebida no arquivo
        print LOG $logitem;

        #Fecha o arquivo
        close LOG;

        #Joga a string no stdout
        print $logitem;

}


#funcao para armazenar as informacoes no syslog
sub SYSLOG{

	my ($msg) = @_; 
	
	#Instancia a conexao com o syslog server
	my $syslog=new Net::Syslog(Facility=>$facility,Priority=>$logLevel,SyslogHost=>$syslogServer);

	#Envia a mensagem para o syslog server
	$syslog->send($msg,Facility=>'user',Priority=>'notice');

}

#Funcao que vai receber como parametro o resultado das consultas (conforme ou nao conforme), vai parsear essa informacao junto ao $args{c} (checks) por meio do array global @comandos e depois, ira passar para a funcao SYSLOG para armazenar essa informacao no SYSLOG server 

sub formatSyslog{

	my @resultado = parseParametro($_[0]);
	my @newComandos = '';
	
	#Insere a string host na posicao 1 do array
	$newComandos[0] = 'host';
	
	#Insere a string conexao na posicao 1 do array
	$newComandos[1] = 'conexao';

	#Concatena os dois arrays 	
	push(@newComandos, @comandos);

	#Instancia um contador para utilizar no array @newComandos
	my $count = 0;

	my $mensagem = '';

	#percorre o array com os resultados e concatena os campos com os valores, por exemplo: ssh=conformes
	foreach(@resultado){

		$mensagem .= $newComandos[$count] . "=" . $_ . ",";
		
		#Incrementa o contador
		$count++;
	}

		#Tira o ultimo caracter, menos a virgula
		$mensagem = substr($mensagem, 0, -1);

	#Envia a mensagem para a funcao SYSLOG, que ira salvar esse log no syslog
	SYSLOG($mensagem);
}

sub validaIP{

       my $ip = $_[0];

       if($ip=~/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ &&(($1<=255  && $2<=255 && $3<=255  &&$4<=255 )))

       {
               LOG "Checando o IP de destino";
               LOG "IP $ip validado";
       }
       else
       {
                LOG "IP invalido";
                LOG "Favor fornecer um IP valido para a consulta";
                &exibeHelp;
       }

}


sub relatorio{

        #Recebe a string como parametro
        my (@report) = @_;

        #Abre o arquivo para relatorio
        open RELATORIO, ">>relatorio.log" or die $!;

        #Armazena a strings recebida no arquivo
        print RELATORIO @report;

        #Fecha o arquivo
        close RELATORIO;

        #Joga a string no stdout
        #print @report;

}


#Funcoes para checar as conformidades/nao conformidades. Todas essas funcoes recebem como parametro a saida do comendo executado no router

#Funcao para checar configuracao do tacacs
sub checkTacacs{

	my @output = @_;
	my @matches = '';

	LOG "Verificando configuracao do tacacs no equipamento";

	#Procurando pela string "CHAVE_DO_CLIENTE_NO_TACACS". Se encontra, retorna "nao conforme"
        @matches = grep { /CHAVE_DO_CLIENTE_NO_TACACS/ } @output;

        if (@matches)
        {
                LOG "Configuracao de chave cliente nao conforme";
                return 1;
        }

	#Procurando pela string "tacacs-server". Se nao encontra, retorna "nao conforme"
	@matches = grep { /tacacs-server/ } @output;

	if (@matches)
	{
		LOG "Configuracao de tacacs encontrada";
		return 0;
	}
	else
	{
		LOG "Configuracao de tacacs nao encontrada";
		return 1;
	}
}

sub checkServices{

	my @output = @_;
	my @matches = '';

        LOG "Verificando configucao de Small Services no equipamento";

	#Procurando pela string "small-servers". Se encontrada, retorna "nao conforme"
	@matches = grep { /small-servers/ } @output;

	if (@matches)
	{
		#Se encontrar, retorna nao conforme
		LOG "Conficuracao de small services ativa";
		return 1;
	}
	else
	{
		LOG "Configuracao de small services desativada";
		return 0;
	}

}

sub checkSyslog{

        my @output = @_;
        my @matches = '';

        LOG "Verificando configucao de Syslog no equipamento";

        #Procurando pela string "logging" seguida por um numero de 1-9. Se encontrada, retorna "nao conforme"
        @matches = grep { /logging [1-9]/ } @output;

        if (@matches)
        {
                #Se encontrar, retorna conforme
                LOG "Configuracao de syslog ativa";
                return 0;
        }
        else
        {
                LOG "Configuracao de syslog desativada";
                return 1;
        }

}

sub checkHttp{

        my @output = @_;
        my @matches = '';

        LOG "Verificando configucao de HTTP server no equipamento";

        #Procurando pela string que comecem com "ip http server". Se encontrada, retorna "nao conforme"
        @matches = grep { /^ip http server/ } @output;

	if (@matches)
       	{
               	#Se encontrar, retorna nao conforme
               	LOG "Configuracao de http server ativada";
                return 1;
  	}
	else
	{
		#Se nao encontrar, retorna conforme	
		LOG "Configuracao de http server desativada";
		return 0;
	}

}

sub checkEncryption{

	my @output = @_;
        my @matches = '';

        LOG "Verificando configucao de Encriptacao de Senha no equipamento";

	#Procurando pela string "password-encryption". Se encontrar, retorna "conforme"
	@matches = grep { /password-encryption/ } @output;

        if (@matches)
        {
                #Se encontrar, retorna conforme
                LOG "Configuracao de Encriptacao de Senha ativada";
                return 0;
        }
        else
        {
                #Se nao encontrar, retorna nao conforme
                LOG "Configuracao de Encriptacao de Senha desativada";
                return 1;
        }


}

sub checkUserOp{

        my @output = @_;
        my @matches = '';

        LOG "Verificando se existe usuario padrao no equipamento";

        #Procurando pela string "operacao". Se encontrar, retorna "conforme"
        @matches = grep { /operacao/ } @output;

        if (@matches)
        {
                #Se encontrar, retorna conforme
                LOG "Usuario padrao configurado";
                return 0;
        }
        else
        {
                #Se nao encontrar, retorna nao conforme
                LOG "Usuario padrao nao configurado";
                return 1;
        }


}

sub checkEnable{

        my @output = @_;
        my @matches = '';

        LOG "Verificando se a senha de enable esta configurada no equipamento";

        #Procurando pela string "enable secret". Se encontrar, retorna "conforme"
        @matches = grep { /enable\ secret/ } @output;

        if (@matches)
        {
                #Se encontrar, retorna conforme
                LOG "Usuario Enable padrao configurado";
                return 0;
        }
        else
        {
                #Se nao encontrar, retorna nao conforme
                LOG "Usuario Enable padrao nao configurado";
                return 1;
        }


}


sub checkAcl3{

        my @output = @_;
        my @matches = '';

        LOG "Verificando configucao de ACLs 3 (acesso) padrao no equipamento";

        #Armazena todas as linhas que contenham a string "permit" no array @matches  
        @matches = grep { /permit/ } @output;

	#Percorre o array testando todas as posicoes, comparando com os ips considerados conhecidos, se achar algum ip desconhecido, retorna nao conforme
	foreach(@matches){
		
		chomp($_);

		if($_ =~ /$ipsToAclOfAccess/){

			LOG "IP $_: Confiavel";

		}else{

			LOG "IP $_: Desconhecido";
			LOG "Configuracao de ACL desativada e/ou erronea";
                	return 1;
		}

	}

        #Se nao achar nenhum ip desconhecido, retorna conforme
        LOG "Configuracao de ACL 3 de acesso ativada";
        return 0;


}

sub checkSnmp{

	my @output = @_;
	my @matches = '';

	LOG "Verificando configuracao de SNMP no equipamento";

	#procurando pela string RW  
	#Teoricamente nao pode haver snmp de escrita habilitado
	@matches = grep { /RW/ } @output;

	if (@matches)
        {
                LOG "Configuracao de SNMP habilitada para RW. Equipamento nao Conforme";
                return 1;
        }


	#Procurando pelas communities permitidas
        @matches = grep { /$snmpCommunities/ } @output;
	
        if (!@matches)
        {
                LOG "Configuracao de SNMP nao encontrada. Equipamento nao Conforme";
                return 1;
        }
	else{

		LOG "Configuracao de SNMP encontrada. Equipamento Conforme";
		return 0;
	}

}

sub checkAcl98{

        my @output = @_;
        my @matches = '';

        LOG "Verificando configucao de ACLs 98 (SNMP) padrao no equipamento";

	#Percorre o array testando todas as posicoes, comparando com os ips considerados conhecidos, se achar algum ip desconhecido, retorna nao conforme
        @matches = grep { /permit/ } @output;

        #Percorre o array testando todas as posicoes, se achar algum ip desconhecido, retorna nao conforme
        foreach my $tmp (@matches){

                chomp($tmp);

                if($tmp =~ /$ipsToSnmpAccess/){

                        LOG "IP $tmp: Confiavel";

                }else{

                        LOG "IP $tmp: Desconhecido";
                        LOG "Configuracao de ACL 98 desativada e/ou configurada de forma erronea";
                        return 1;
                }

        }

        #Se nao achar nenhum ip desconhecido, retorna conforme
        LOG "Configuracao de ACL 98 de SNMP OK";
        return 0;


}





#Funcao para testar se o SSH esta e suportado e esta habilitado (Somente telnet)
sub checkSsh{

	my @output = @_;
        my @matches = '';
	my $host = $_[1];
	my $protocolo = '';

	LOG "Verificando configuracao de SSH no equipamento";

	#Procurando pela string "k9". 
        @matches = grep { /System*k9*/ } @output;

	if (!@matches)
	{
		LOG "SSH nao suportado. Equipamento Conforme";	
		return 0;
	}

	#Verificando se o telnet ainda esta habilitado
	$protocolo = &testaProtocolo($host); 

       	if ((@matches) && ($protocolo == '1'))
       	{
               LOG "SSH suportado, mas telnet ainda habilitado, portanto nao conforme";
               return 1;
       	}

}


#Funcao para checar qual comando deve ser executado (conforme parametro passado no inicio do script: tacacs, ssh etc...) e retorna o comando completo a ser executado no Router
sub checkComando{

        my $comando = $_[0];
	my $comandoRouter = '';

        if ($comando eq 'tacacs')
        {
		$comandoRouter = 'show run | i tacacs';
		return $comandoRouter;	
		exit 0;
        } 
	elsif ($comando eq 'ssh')
	{
		$comandoRouter = 'show version | i System image file';
                return $comandoRouter;
                exit 0;
	}
	elsif ($comando eq 'services')
	{
		$comandoRouter = 'show run | i small-servers';
                return $comandoRouter;
                exit 0;
	}
	elsif ($comando eq 'syslog')
        {
                $comandoRouter = 'show run | i logging';
                return $comandoRouter;
                exit 0;
        }
	elsif ($comando eq 'http')
        {
                $comandoRouter = 'show run | i http server';
                return $comandoRouter;
                exit 0;
        }
	elsif ($comando eq 'encryption')
        {
                $comandoRouter = 'show run | i password-encryption';
                return $comandoRouter;
                exit 0;
        }

	elsif ($comando eq 'userOp')
        {
                $comandoRouter = 'show run | i username';
                return $comandoRouter;
                exit 0;
        }

	elsif ($comando eq 'enable')
        {
                $comandoRouter = 'show run | i secret';
                return $comandoRouter;
                exit 0;
        }

	elsif ($comando eq 'acl3')
        {
                $comandoRouter = 'show access-lists 3';
                return $comandoRouter;
                exit 0;
        }

	elsif ($comando eq 'acl98')
        {
                $comandoRouter = 'show access-lists 98';
                return $comandoRouter;
                exit 0;
        }

	elsif ($comando eq 'snmp')
        {
                $comandoRouter = 'show run | i snmp';
                return $comandoRouter;
                exit 0;
        }

	else{
		LOG "Configuracao nao encontrada para o comando $comando";
		&exibeHelp;
	}

}


#Funcao para testar qual protocolo deve ser utilizado para realizacao do teste
sub testaProtocolo {

	LOG "Testando portas abertas\n";

	my $timeout = 2;
	my $hostname = $ARGV[0];
	my $portnumber = '23';
	my $host = shift || $hostname;
	my $port = shift || $portnumber;
	my $proto = getprotobyname('tcp');
	my $iaddr = inet_aton($host);
	my $paddr = sockaddr_in($port, $iaddr);

	socket(SOCKET, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";

	eval {
	local $SIG{ALRM} = sub { die "timeout" };
  	alarm($timeout);
	connect(SOCKET, $paddr) || error();
	alarm(0);
	};

	LOG "Verificando protocolo\n";

	if (!$@) {
                $args{p} = 'telnet';
		LOG "Protocolo encontrado: telnet"; 
		return 1;
        } else {
                $args{p} = 'ssh';
		LOG "Protocolo encontrado: ssh"; 
		return 2;
                }


}

sub exibeHelp {
                print "Modo de usar: $0 -h [host] | -F [FILE] -p [telnet|ssh|any] -c [tacacs,ssh,services,syslog,snmp,http,encryption,userOp,enable,acl3] \n\n";

		print "F - Arquivo com equipamentos a serem verificados\n";
                print "h - Host a ser verificado pelo script\n";
		print "p - Protocolo utilizado para conexao: telnet, ssh ou any\n";
		print "c - Validacao a ser executada: tacacs,ssh,services,syslog,snmp,http,encryption,userOp,enable,acl3,acl98 etc.\n";
                exit 0;
}

#Funcao para conectar em equipamentos e executar comandos, (Recebe como parametro $host, $userAcesso, $senhaAcesso, $senhaEnable e usa o array global @comandos) 

sub conectaEquipamento{
	
	#Recebe os paramestros para conectar no equipamento
	my $protocolo = $_[0];
	my $host = $_[1];
	my $userAcesso = $_[2];
	my $senhaAcesso = $_[3];
	my $senhaEnable = $_[4];
	my $authLocal = $_[5];
	my $comandoRouter = '';
	my $conforme = '';
	my $resultado = '';
	my $conexao = '';
	my @output = '';
	my $ssh = '';
	our $session = '';

	#Se for ssh
	if($protocolo eq 'ssh'){

		#Loga no equipamento utilizando o protocolo SSH	
		LOG "Iniciando a conexao via SSH";
		LOG "Conectando no equipamento $host";
		$ssh = Net::SSH::Perl->new($host);
	
		$ssh->login($userAcesso, $senhaAcesso);
		my($stdout, $stderr, $exit) = $ssh->cmd("show clock");

	}

	#Testa se a conexao e local ou nao, como criterio, ele recebe um parametro a mais, o parametro $_[4]	
	if(($authLocal) && ($authLocal eq '1')){
        $conexao = $authLocal;
        LOG "Logado com credenciais locais";
        }


	#Remove quebra de linha do relatorio
	my $tempHost = $host; 
	chomp($tempHost);
	#Insere o ip do roteador no relatorio e a informacao OK, na coluna conexao
	$resultado .= $tempHost . "," . "OK,";


	#Todos os comandos passados como parametros serao analisados e se estiverem corretos serao executados

	foreach my $tmp (@comandos){

		LOG "Iniciando verificacao da configucao: $tmp";
		$comandoRouter = checkComando($tmp);

			#Se for ssh
	        	if($protocolo eq 'ssh'){
				@output =  $ssh->cmd($comandoRouter);
			}

	#Verificando qual comando sera executado. Uma vez identificado o comando, sera chamada a funcao equivalente para verificar a conformidade ou nao do item

	if ($tmp eq 'tacacs')
        {
                $conforme = &checkTacacs(@output);

		#checa se a variavel conexao esta preenchida, se tiver ele ira retornar nao conforme, pq o login foi feito com credencial local

		if($conexao eq '1')
		{
			$resultado .= "Nao Conforme,";
		}else{

			if($conforme == 0){
				$resultado .= "Conforme,";
			}else{
				$resultado .= "Nao Conforme,";
			}
		}
        }
        elsif ($tmp eq 'ssh')
        {
                $conforme = &checkSsh(@output,$host);

		if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }
        elsif ($tmp eq 'services')
        {
                $conforme = &checkServices(@output);

		if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }
	elsif ($tmp eq 'syslog')
        {
                $conforme = &checkSyslog(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }
	elsif ($tmp eq 'http')
        {
                $conforme = &checkHttp(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }

	elsif ($tmp eq 'encryption')
        {
                $conforme = &checkEncryption(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }
 	elsif ($tmp eq 'userOp')
        {
                $conforme = &checkUserOp(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }

	elsif ($tmp eq 'enable')
        {
                $conforme = &checkEnable(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }

	elsif ($tmp eq 'acl3')
        {
                $conforme = &checkAcl3(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }


	elsif ($tmp eq 'acl98')
        {
                $conforme = &checkAcl98(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }

	elsif ($tmp eq 'snmp')
        {
                $conforme = &checkSnmp(@output);

                if($conforme == 0){
                        $resultado .= "Conforme,";
                }else{
                        $resultado .= "Nao Conforme,";
                }

        }

        else{
                LOG "Configuracao: $tmp nao encontrada";
                &exibeHelp;
        }

	}

	#Envia a informacao para armazenar no syslog
	LOG "Enviando os resultados para serem armazenados no syslog";
	formatSyslog($resultado);

	#Adiciona conteudo da variavel resultado do relatorio

	&relatorio ($resultado . "\n");

	if($protocolo eq 'telnet'){
		$session->close;
	}
	elsif($protocolo eq 'ssh'){
	}
}

#Declaracao / definicao de variaveis
my $host = $args{h};

#Definicao de credenciais locais

my $userAcesso = 'userLocal';
my $senhaAcesso = 'passLocal';
my $senhaEnable = 'passEnableLocal';

my $userAcessoTacacs = 'userTacacs';
my $senhaAcessoTacacs = 'passLocal';
my $senhaEnableTacacs = 'passEnableLocalTacacs';


#Definicao do protocolo a ser utilizado
my $protocolo = $args{p};

#Define uma variavel para saber se foi possivel logar com usuario local ou nao
my $conexaoUserLocal = '';

my $authLocal = 1;


#Verifica se a verificacao sera efetuada em um unico host e se sera atravez de uma lista em um arquivo 

	if($args{h}){
        	LOG "Iniciando a verificacao no host $host";

		#Verifica o protocolo passado como parametro, se for telnet a funcao para conexao telnet sera instanciada
		#Aqui ele tentara fazer a conexao por telnet, se nao conseguir ele ira tratar o erro, verificando se existe a string "timed-out" ou "Tempo esgotado". Se nao houver, presupoe-se que seja um problema de credenciais. O script ira testar se a string "access denied" existe. Se existir, ele ira tentar fazer login com as credenciais do tacacs, se mesmo assim nao conseguir, o equipamento sera considerado inacessivel/indeterminado

		if($protocolo eq 'ssh')
		{
				#Tenta fazer a conexao com usuario local, se nao conseguir vai capturar o erro com o catch. Quando a conexao e efetuada com usuario local, um parametro e mais e passado ($authLocal), para que a funcao saiba com qual credencial o acesso foi garantido. Esse parametro sera capturado na funcao conectaEquipamento como $_[5]
                        try{
		        	conectaEquipamento($protocolo, $host, $userAcesso, $senhaAcesso, $senhaEnable, $authLocal);
			}
			 catch
                        {
                                LOG "ERRO: Nao foi possivel conectar no equipamento $host";
                                warn "Erro: $_";
				#vai verificar que o erro foi devido a timed-out, se for indicara isso no relatorio
				if($_ =~ /timed-out|Tempo\ esgotado/){
				#Coloca a informacao de erro de conexao no log
				LOG "ERRO: Time out na conexao";
                                #Coloca a informacao no relatorio
                                #remove a quebra de linha
                                chomp($host);
                                my $resultado = "$host,Time Out";

				#Envia a informacao para o syslog
				formatSyslog($resultado);

				#Envia a informacao para o relatorio
                                &relatorio ($resultado . "\n");
				}
				#Se nao for, e receber erro com relacao a credencial, ele tentara fazer a conexao com usuario do tacacs
				elsif ($_ =~ /Permission\ denied/){
					LOG "Nao foi possivel logar com usuario local no equipamento";
					LOG "Tentando fazer conexao com as credenciais remotas(tacacs)";
		 			try{
						conectaEquipamento($protocolo, $host, $userAcessoTacacs, $senhaAcessoTacacs, $senhaEnableTacacs);
                                	}
                               		catch{
						#Coloca a informacao no relatorio
						LOG "Nao foi possivel logar no equipamento com usuario do tacacs";
		                                #remove a quebra de linha
               			                chomp($host);
                               			my $resultado = "$host,Credenciais invalidas";
						#Envia a informacao para o syslog
						formatSyslog($resultado);

		                                &relatorio ($resultado . "\n");
                                	}
				#Fecha o primeiro catch
				}
			#Fecha o segundo if
			}

                        #Se nao, ira chamar a funcao ssh

		}elsif ($protocolo eq 'telnet')
		{
		        LOG "Conexao por telnet ainda nao suportada";
		} 	
	#Se nao for para um unico host, sera para varios por meio de um arquivo
 	} elsif($args{F}) {
	        LOG "Iniciando a verificacao nos hosts do arquivo $args{F}";
       		abreArquivo ($args{F});

	#Inicia uma variavel para ser o contador de posicoes de index do array global @listaPortas	
	my $temp = 1;

	#Enquanto existirem hosts no array global @listaHosts esse for sera executado, para testar o protocolo e efetuar cada conexao 
		foreach(@listaHosts){

			#Adiciona o host contido no arquivo na variavel host
			$host = $_;

			#verifica o protocolo conforme a porta inserida no arquivo
			my $protocolo = testaPorta($listaPortas[$temp]);

			#Aqui ele tentara fazer a conexao, se nao conseguir ele ira tratar o erro, verificando se existe a string timed-out. Se nao houver, presupoe-se que seja um problema de credenciais. O script ira testar se a string "access denied" existe. Se existir, ele ira tentar fazer login com as credenciais do tacacs, se mesmo assim nao conseguir, o equipamento sera considerado inacessivel/indeterminado

				#Tenta fazer a conexao com usuario local, se nao conseguir vai capturar o erro com o catch. Quando a conexao e efetuada com usuario local, um parametro e mais e passado ($authLocal), para que a funcao saiba com qual credencial o acesso foi garantido. Esse parametro sera capturado na funcao conectaEquipamento como $_[5]
				try{
                        		conectaEquipamento($protocolo, $host, $userAcesso, $senhaAcesso, $senhaEnable, $authLocal);
				}
				catch
        			{
					LOG "ERRO: Nao foi possivel conectar no equipamento $host";
           				warn "Error: $_";
					if($_ =~ /timed-out|Tempo\ esgotado/){
					#Coloca a informacao no relatorio
					LOG "ERRO: Time out na conexao";
					#remove a quebra de linha
			        	chomp($host);
					my $resultado = "$host,Time Out";

					#Envia a informacao para syslog
					formatSyslog($resultado);

					#Envia a informacao para o relatorio
					&relatorio ($resultado . "\n");
}
                                #Se nao for, e receber erro com relacao a credencial, ele tentara fazer a conexao com usuario do tacacs
                                elsif ($_ =~ /Permission\ denied/){
                                        LOG "Nao foi possivel logar com usuario local no equipamento";
                                        LOG "Tentando fazer conexao com as credenciais remotas(tacacs)";
                                        try{
                                                conectaEquipamento($protocolo, $host, $userAcessoTacacs, $senhaAcessoTacacs, $senhaEnableTacacs);
                                        }
                                        catch{
						warn "Error: $_";
                                                #Coloca a informacao no relatorio
                                                LOG "Nao foi possivel logar no equipamento com usuario do tacacs";
                                                #remove a quebra de linha
                                                chomp($host);
                                                my $resultado = "$host,Credenciais Invalidas";

						#Envia a informacao para o syslog
						formatSyslog($resultado);

						#Envia a informacao para o relatorio
                                                &relatorio ($resultado . "\n");
                                        }
                                #Fecha o primeiro catch
                                }
                        #Fecha o segundo if

				}
                	}

			$temp++;
}
