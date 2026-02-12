```text
      :::::::::       :::::::::       :::::::: 
     :+:    :+:      :+:    :+:     :+:    :+: 
    +:+    +:+      +:+    +:+     +:+         
   +#++:++#+       +#++:++#:      +#++:++#++   
  +#+             +#+    +#+            +#+    
 #+#             #+#    #+#     #+#    #+#     
###             ###    ###      ########  
```
<p align="center">
  <h1>PRS v1.6.0</h1>
  <h3>Passive Reconnaissance Scanner</h3>
  <p>
    <strong>취약점 스캐너</strong><br>
  </p>

  <p>
    <a href="https://github.com/MOYARU/PRS-project/releases">
      <img src="https://img.shields.io/github/v/release/MOYARU/PRS-project?color=5865F2" alt="Release">
    </a>
    <a href="https://github.com/MOYARU/PRS-project/stargazers">
      <img src="https://img.shields.io/github/stars/MOYARU/PRS-project?style=social" alt="Stars">
    </a>
    <img src="https://img.shields.io/github/go-mod/go-version/MOYARU/PRS-project?color=00ADD8" alt="Go">
    <img src="https://img.shields.io/github/license/MOYARU/PRS-project?color=green" alt="MIT">
  </p>
</p>

---

### 핵심 특징
- 한국어 ↔ 영어 실시간 전환
- 직관적인 콘솔 출력 +  HTML 보고서 생성
- 크롤링 + 폼 추출 지원

## 빌드
```
git clone https://github.com/MOYARU/PRS-project.git
cd PRS-project
go build -o prs.exe (본인 운영체제에 따라)
./prs
prs example.com
```

### 빠른 시작

**./prs**

```bash
# 기본 스캔
prs https://example.com

# 깊이 3 + JSON 출력
prs https://example.com --depth 3 --json

# 액티브 모드 (주의 필요)
prs https://example.com --active

# 딜레이 300ms
prs https://example.com --delay 300
```

## roadmap
검사를 좀더 진득하게(?)
