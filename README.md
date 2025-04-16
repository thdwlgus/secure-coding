# Tiny Platform - 중고거래 웹 플랫폼

중고 물품을 등록하고, 채팅을 통해 사용자 간에 안전하게 거래할 수 있는 웹 기반 중고거래 플랫폼이다.  
상품 등록, 검색, 포인트 송금, 실시간 채팅, 관리자 통제 기능 등 실제 서비스에 가까운 기능을 포함하고 있다.


## 주요 기능

| 기능 영역 | 기능 설명 |
| -------- | -------- |
| 사용자 기능 | 회원가입, 로그인, 마이페이지, 비밀번호 변경 |
| 상품 기능 | 상품 등록, 수정, 삭제, 검색, 상세 보기 |
| 채팅 기능 | 사용자 간 1:1 채팅, 그룹 채팅 |
| 거래 기능 | 포인트 기반 송금, 거래 내역 확인 |
| 신고 기능 | 사용자 및 상품 신고 기능 |
| 관리자 기능 | 사용자/상품/신고/메시지/거래 내역 관리, 통계 대시보드 제공 |


## 환경 설정 및 실행 방법

### 1. 요구 환경

- Python 3.10 이상
- SQLite3
- Flask, Flask-SocketIO
- 기타 라이브러리는 `requirements.txt` 참고


### 2. 설치

```bash
python -m venv venv                # 구축 환경은 선택
source venv/bin/activate           # Linux/macOS
venv\Scripts\activate.bat          # Windows

pip install -r requirements.txt    # 패키지 설치
```

### 3. 실행

```bash
python3 app.py