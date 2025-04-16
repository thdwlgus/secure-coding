# Tiny Platform - 중고거래 웹 플랫폼

중고 물품을 등록하고, 채팅을 통해 사용자 간에 안전하게 거래할 수 있는 웹 기반 중고거래 플랫폼이다.  
상품 등록, 검색, 포인트 송금, 실시간 채팅, 관리자 통제 기능 뿐만 아니라 CSRF 보호, XSS 방지, HTTPS 통신, 세션 보안, 신고 남용 방지, 보안 헤더 적용 등 **시큐어 코딩 기반 보안 강화 기능**이 포함되어 있다.



## 주요 기능

| 기능 영역      | 기능 설명 |
|----------------|----------------|
| 사용자 기능     | 회원가입, 로그인, 마이페이지, 비밀번호 변경 |
| 상품 기능       | 상품 등록, 수정, 삭제, 검색, 상세 보기 |
| 채팅 기능       | 사용자 간 1:1 채팅, 그룹 채팅 (실시간 WebSocket 기반) |
| 거래 기능       | 포인트 기반 송금, 거래 내역 확인 |
| 신고 기능       | 사용자 및 상품 신고 기능, 신고 중복 방지 |
| 관리자 기능     | 사용자/상품/신고/메시지/거래 내역 관리, 통계 대시보드 제공 |
| 보안 기능       | CSRF 보호<br>XSS 방어<br>HTTPS + WSS 기반 통신<br>WebSocket 인증 및 Rate Limiting<br>Content-Security-Policy, Secure/HttpOnly 쿠키<br>DB 파일 권한 제한 (0600)<br> 인증되지 않은 사용자 접근 차단 |



## 환경 설정 및 실행 방법

### 1. 요구 환경

- Python 3.10 이상
- SQLite3
- Flask
- Flask-SocketIO
- eventlet
- 기타 라이브러리는 `requirements.txt` 참고


### 2. 설치

```bash
python -m venv venv                   # 구축 환경은 선택
source venv/bin/activate              # Linux/macOS
venv\Scripts\activate.bat             # Windows

pip install -r requirements.txt       # 패키지 설치
```

### 3. 인증서 생성 (HTTPS + WSS)

```bash
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
```


### 4. 실행 방법
```bash
python3 app.py                        # HTTP + WSS 모드로 실행
```
- 기본 접속 URL : https://localhost:5000
- 인증서가 존재하면 https://localhost:5000 으로 자동 실행
- WebSocket도 WSS 프로토콜을 통해 암호화 진행


## 기본 관리자 계정
최초 실행 시 자동 생성 : 
- 이메일 : `admin@example.com`
- 비밀번호 : `admin1234`
> 관리자 계정은 사용자, 상품, 메시지, 신고, 차단 관리 등의 기능을 수행할 수 있다.