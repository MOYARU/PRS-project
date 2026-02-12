```text
      :::::::::       :::::::::       :::::::: 
     :+:    :+:      :+:    :+:     :+:    :+: 
    +:+    +:+      +:+    +:+     +:+         
   +#++:++#+       +#++:++#:      +#++:++#++   
  +#+             +#+    +#+            +#+    
 #+#             #+#    #+#     #+#    #+#     
###             ###    ###      ########  
```
# PRS v1.6.0
### *Passive Reconnaissance Scanner*
### PRS focuses on risk visibility, not exploitation.

## Overview
#### PRS is a terminal-based web security scanner focused on identifying security misconfigurations, insecure defaults, and design-level risks.
#### It prioritizes clarity and safety over aggressive exploitation, providing actionable insights without attempting to compromise the target system.


## Design Philosophy
#### PRS is designed with the following principles:
1. Prefer passive analysis over active exploitation
2. Detect misconfigurations and insecure design patterns
3. Avoid intrusive or destructive behavior
4. Clearly communicate uncertainty and possible false positives
#### PRS does not attempt to exploit vulnerabilities.
#### Instead, it highlights conditions that may lead to security issues.

## Output Example
```
[HIGH] IDOR Possible
Numeric identifier changed: /resource/123 → /resource/124
Response behavior differed
Manual verification recommended
```

## 사용방법
#### 해당 툴은 CLI툴입니다.
#### PRS를 설치하고 프롬프트에서 PRS.EXE를 실행합니다.
#### .\PRS
직접 빌드도 가능합니다.
#### prs (example.com) 으로 스캔합니다.
#### 옵션 소개
1. --active : active모드를 이용합니다.
2. --crawler : 크롤러를 사용합니다.
3. --depth : 크롤링 깊이를 설정합니다(기본값 : 2)
4. --json : 결과 리포트를 JSON으로 받습니다.
5. --html : HTML형식의 결과 리포트를 받습니다.
6. --delay : 리퀘스트 사이에 딜레이를 넣습니다. 서버의 과부하를 방지합니다.

#### 한글 / 영어 선택이 추가되었으며 방향키로 선택 가능합니다.

## roadmap
1. 심층 스캔(Deep Scan) 로직 고도화 및 정밀도 향상
2. HTTP 프록시 서버 모드 추가 (Passive Analysis 강화)
3. Interactive 모드 내 리피터(Repeater) 기능 구현

## Known Limitations
1. **GET Parameter Only**: 현재 스캐너는 URL 쿼리 스트링(GET 파라미터)에 대해서만 인젝션 점검을 수행합니다. POST Body(로그인 폼 등)에 대한 자동 퍼징은 지원하지 않습니다.
2. **Error-Based SQLi Focus**: SQL Injection 점검은 주로 DB 에러 메시지 노출 여부를 확인합니다. 에러가 억제된 경우(Boolean-based) 탐지되지 않을 수 있습니다.
3. **Active Mode Required**: 인젝션 및 XSS 점검은 `--active` 옵션을 켜야만 동작합니다.
