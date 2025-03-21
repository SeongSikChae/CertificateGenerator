SSL 인증서 발급도구 (Certificate Generator)
=========================================

사용법
------

### CA 인증서 생성

#### ca_template.yaml
<pre>
# CA 인증서 생성을 위한 설정
OrganizationName: CA
CommonName: localhost
Days: 7300 # (만료기한: 현재시간 + $Days)
KeyFile: "keys/ca.key" # 인증서 키 파일 생성 위치
CertificateFile: "certs/ca.crt" # 인증서 파일 생성 위치
StoreFile: "store/ca.p12" # PKCS12 파일 생성 위치
StorePassword: 1234 # PKCS12 패스워드
Alias: ca
</pre>

<pre>
CertificateGenerator.exe --config ca.yaml --mode CA
</pre>

### Middle CA 인증서 생성

### middle_ca_template.yaml
<pre>
# Middle CA 인증서 생성을 위한 설정
OrganizationName: MiddleCA
CommonName: localhost
Days: 7300
KeyFile: "keys/middle_ca.key"
CertificateFile: "certs/middle_ca.crt"
StoreFile: "store/middle_ca.p12"
StorePassword: 1234
Alias: middle_ca
CAStoreFile: "store/ca.p12" # CA PKCS12 파일 위치
CAStorePassword: 1234 # CA PKCS12 패스워드
CAKeyFile: "keys/ca.key" # CA 인증서 키 파일 위치
WithCA: false # 서버 인증서 PKCS12 파일에 CA 인증서를 포함할 것인지 여부
</pre>

<pre>
CertificateGenerator.exe --config middle_ca_template.yaml --mode MIDDLE_CA
</pre>

### 서버 인증서 생성

#### server_template.yaml
<pre>
OrganizationName: SERVER
CommonName: localhost # (서버 도메인 또는 IP)
Days: 3650 # (만료기한: 현재시간 + $Days)
KeyFile: "keys/server.key" # 인증서 키 파일 생성 위치
CertificateFile: "certs/server.crt" # 인증서 파일 생성 위치
StoreFile: "store/server.p12" # PKCS12 파일 생성 위치
StorePassword: 1234 # PKCS12 패스워드
Alias: server
CAStoreFile: "store/middle_ca.p12" # CA PKCS12 파일 위치
CAStorePassword: 1234 # CA PKCS12 패스워드
# 추가적인 서버 도메인
AlternativeNames:
- "localhost"
# 추가적인 서버 IP
AlternativeAddresses:
- "127.0.0.1"    
CAKeyFile: "keys/middle_ca.key" # CA 인증서 키 파일 위치
WithCA: true # 서버 인증서 PKCS12 파일에 CA 인증서를 포함할 것인지 여부
</pre>

<pre>
CertificateGenerator.exe --config server.yaml --mode SERVER
</pre>

### 클라이언트 인증서 생성

#### client_template.yaml
<pre>
OrganizationName: CLIENT
CommonName: localhost # 클라이언트 도메인, IP, 명칭
Email: localhost@localhost # 클라이언트 이메일 주소
Days: 365 # (만료기한: 현재시간 + $Days)
KeyFile: "keys/client.key" # 인증서 키 파일 생성 위치
CertificateFile: "certs/client.crt" # 인증서 파일 생성 위치
StoreFile: "store/client.p12" # PKCS12 파일 생성 위치
StorePassword: 1234 # PKCS12 패스워드
Alias: client
CAStoreFile: "store/ca.p12" # CA PKCS12 파일 위치
CAStorePassword: 1234 # CA PKCS12 패스워드
CAKeyFile: "keys/ca.key" # CA 인증서 키 파일 위치
WithCA: false # 서버 인증서 PKCS12 파일에 CA 인증서를 포함할 것인지 여부
</pre>

<pre>
CertificateGenerator.exe --config client.yaml --mode CLIENT
</pre>
