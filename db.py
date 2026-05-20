import streamlit as st
import os
import hashlib

# httpx 라이브러리 체크 및 설치
try:
    import httpx
except ImportError:
    os.system("pip install httpx")
    import httpx

# 암호화 부품 가져오기
from crypto_util import encrypt_password, decrypt_password

# 페이지 기본 설정
st.set_page_config(page_title="나만의 비밀번호 관리자", page_icon="🔐", layout="centered")

st.title("🔐 나만의 안전한 비밀번호 관리자")
st.caption("수정 및 삭제 시 마스터 비밀번호 재인증을 요구하여 보안성을 극대화했습니다.")
st.markdown("---")

# Supabase 연결 설정 (본인의 정보 유지)
base_url = "https://tntjmtyomhnlheyskgvi.supabase.co"
# 기존 코드: api_key = "블라블라내비밀키"
# 변경할 코드: 스트림릿 비밀 금고에서 키를 꺼내오도록 수정
api_key = st.secrets["SUPABASE_KEY"]

final_key = api_key.strip()
headers = {
    "apikey": final_key,
    "Authorization": f"Bearer {final_key}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

# 테이블 주소들
passwords_url = f"{base_url.strip()}/rest/v1/passwords"
auth_url = f"{base_url.strip()}/rest/v1/master_auth"

# 비밀번호 단방향 암호화(해시) 함수
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# -----------------------------------------------------------------
# [체크 단계] 기존에 등록된 마스터 비밀번호가 있는지 확인
# -----------------------------------------------------------------
is_registered = False
existing_hash = ""

with httpx.Client(headers=headers) as client:
    try:
        res = client.get(auth_url)
        if res.status_code == 200 and res.json():
            is_registered = True
            existing_hash = res.json()[0]['password_hash']
    except Exception as e:
        st.error(f"보안 서버 연결 중 오류 발생: {e}")

# -----------------------------------------------------------------
# 🔒 화면 구성: 미등록 상태 vs 등록 상태
# -----------------------------------------------------------------
if not is_registered:
    st.info("👋 안녕하세요! 사용할 **마스터 비밀번호**를 최초 등록해 주세요.")
    with st.form("init_auth_form"):
        reg_pw = st.text_input("사용할 마스터 비밀번호 입력", type="password")
        reg_pw_confirm = st.text_input("비밀번호 확인", type="password")
        reg_btn = st.form_submit_button("🔑 마스터 비밀번호 등록 및 시작")
        
        if reg_btn:
            if not reg_pw:
                st.error("비밀번호를 입력해 주세요.")
            elif reg_pw != reg_pw_confirm:
                st.error("두 비밀번호가 일치하지 않습니다.")
            else:
                hashed = hash_password(reg_pw)
                with httpx.Client(headers=headers) as client:
                    sub_res = client.post(auth_url, json={"password_hash": hashed})
                    if sub_res.status_code == 201:
                        st.success("🎉 성공적으로 등록되었습니다! 새로고침(F5)을 눌러주세요.")
                        st.rerun()
                    else:
                        st.error("등록 실패")

else:
    st.sidebar.header("🔑 인증 센터")
    input_pw = st.sidebar.text_input("마스터 비밀번호 입력", type="password")
    
    if not input_pw:
        st.info("👈 왼쪽 사이드바에 **마스터 비밀번호**를 입력해야 문이 열립니다.")
    elif hash_password(input_pw) != existing_hash:
        st.sidebar.error("❌ 비밀번호가 틀렸습니다! 다시 입력해 주세요.")
    else:
        st.sidebar.success("🔓 인증 성공! 환영합니다.")
        
        # ⚙️ 마스터 비밀번호 변경 섹션
        with st.sidebar.expander("🛠️ 마스터 비밀번호 변경하기"):
            new_master_pw = st.text_input("새로운 마스터 비밀번호", type="password")
            confirm_master_pw = st.text_input("새 비밀번호 확인", type="password")
            change_btn = st.button("🔐 비밀번호 일괄 변경 실행")
            
            if change_btn:
                if not new_master_pw or new_master_pw != confirm_master_pw:
                    st.error("새 비밀번호 입력을 확인해 주세요.")
                else:
                    with st.spinner("재암호화 진행 중..."):
                        with httpx.Client(headers=headers) as client:
                            try:
                                res_pw = client.get(passwords_url)
                                if res_pw.status_code == 200:
                                    all_data = res_pw.json()
                                    for item in all_data:
                                        decrypted = decrypt_password(item['encrypted_password'], input_pw)
                                        if decrypted.startswith("❌"): continue
                                        new_encrypted = encrypt_password(decrypted, new_master_pw)
                                        client.patch(f"{passwords_url}?id=eq.{item['id']}", json={"encrypted_password": new_encrypted})
                                    
                                    new_hash = hash_password(new_master_pw)
                                    client.patch(f"{auth_url}?select=*", json={"password_hash": new_hash})
                                    st.sidebar.success("🎉 변경 성공! 다시 로그인해 주세요.")
                                    st.rerun()
                            except Exception as e:
                                st.sidebar.error(f"오류: {e}")

        # -----------------------------------------------------------------
        # 🔒 [메인 화면] 기능 구현
        # -----------------------------------------------------------------
        tab1, tab2 = st.tabs(["➕ 새 비밀번호 등록", "📋 내 비밀번호 목록"])

        # [TAB 1] 새 비밀번호 등록
        with tab1:
            st.subheader("새로운 계정 정보 추가")
            with st.form("add_form", clear_on_submit=True):
                site_name = st.text_input("사이트 이름 (예: 네이버, 구글, 댕댕쓰 관리자)")
                site_url = st.text_input("사이트 주소 (선택 사항)")
                login_id = st.text_input("로그인 아이디(ID)")
                login_pw = st.text_input("로그인 비밀번호(PW)", type="password")
                memo = st.text_area("메모 (선택 사항)")
                
                submit_btn = st.form_submit_button("🔒 안전하게 암호화하여 저장")
                
                if submit_btn:
                    if not site_name or not login_id or not login_pw:
                        st.warning("사이트 이름, 아이디, 비밀번호는 필수 입력 항목입니다!")
                    else:
                        encrypted_pw = encrypt_password(login_pw, input_pw)
                        payload = {
                            "site_name": site_name,
                            "site_url": site_url,
                            "login_id": login_id,
                            "encrypted_password": encrypted_pw,
                            "memo": memo
                        }
                        with httpx.Client(headers=headers) as client:
                            res = client.post(passwords_url, json=payload)
                            if res.status_code == 201:
                                st.success(f"🎉 '{site_name}' 계정 정보가 암호화되어 보관되었습니다!")
                                st.rerun()

        # [TAB 2] 내 비밀번호 목록 조회 (수정/삭제 기능 탑재)
        with tab2:
            st.subheader("보관된 비밀번호 목록")
            with httpx.Client(headers=headers) as client:
                res = client.get(passwords_url)
                if res.status_code == 200:
                    data = res.json()
                    if not data:
                        st.write("아직 저장된 비밀번호가 없습니다.")
                    else:
                        st.write(f"현재 총 **{len(data)}개**의 계정이 보관 중입니다.")
                        st.markdown("---")
                        
                        for idx, item in enumerate(data):
                            # 각 계정 정보를 접이식 상자(Expander)로 구현
                            with st.expander(f"🌐 {item['site_name']} ({item['login_id']})"):
                                st.write(f"**사이트 주소:** {item['site_url'] if item['site_url'] else '없음'}")
                                st.write(f"**아이디:** `{item['login_id']}`")
                                
                                decrypted_pw = decrypt_password(item['encrypted_password'], input_pw)
                                st.success(f"🔓 **실제 비밀번호:** **{decrypted_pw}**")
                                if item['memo']:
                                    st.write(f"📝 **메모:** {item['memo']}")
                                
                                st.markdown("---")
                                
                                # 🛠️ 핵심 기능: 수정 및 삭제 서브 창 구성
                                col1, col2 = st.columns(2)
                                
                                # [수정하기 서브 창]
                                with col1:
                                    with st.popover("✏️ 정보 수정하기"):
                                        st.write("📝 **수정할 내용을 입력하세요**")
                                        edit_site_name = st.text_input("사이트 이름", value=item['site_name'], key=f"edit_site_{idx}")
                                        edit_site_url = st.text_input("사이트 주소", value=item['site_url'] if item['site_url'] else "", key=f"edit_url_{idx}")
                                        edit_id = st.text_input("아이디", value=item['login_id'], key=f"edit_id_{idx}")
                                        edit_pw = st.text_input("새 비밀번호 (비워두면 기존 유지)", type="password", key=f"edit_pw_{idx}")
                                        edit_memo = st.text_area("메모", value=item['memo'] if item['memo'] else "", key=f"edit_memo_{idx}")
                                        
                                        st.markdown("---")
                                        # 🔐 보안 검증 장치
                                        edit_auth = st.text_input("⚠️ 인증: 마스터 비밀번호 입력", type="password", key=f"edit_auth_{idx}")
                                        edit_submit = st.button("💾 수정사항 저장", key=f"edit_btn_{idx}")
                                        
                                        if edit_submit:
                                            if hash_password(edit_auth) != existing_hash:
                                                st.error("❌ 마스터 비밀번호가 틀려 수정할 수 없습니다.")
                                            else:
                                                # 비밀번호를 새로 바꾼 경우엔 새로 암호화, 아니면 기존 암호문 그대로 사용
                                                final_encrypted = encrypt_password(edit_pw, edit_auth) if edit_pw else item['encrypted_password']
                                                
                                                update_payload = {
                                                    "site_name": edit_site_name,
                                                    "site_url": edit_site_url,
                                                    "login_id": edit_id,
                                                    "encrypted_password": final_encrypted,
                                                    "memo": edit_memo
                                                }
                                                with httpx.Client(headers=headers) as client:
                                                    up_res = client.patch(f"{passwords_url}?id=eq.{item['id']}", json=update_payload)
                                                    if up_res.status_code in [200, 204]:
                                                        st.success("🎉 정보가 안전하게 수정되었습니다!")
                                                        st.rerun()
                                                    else:
                                                        st.error("수정 실패")
                                
                                # [삭제하기 서브 창]
                                with col2:
                                    with st.popover("🗑️ 정보 삭제하기"):
                                        st.write("⚠️ **정말 이 정보를 데이터베이스에서 영구 삭제하시겠습니까?**")
                                        # 🔐 보안 검증 장치
                                        delete_auth = st.text_input("⚠️ 인증: 마스터 비밀번호 입력", type="password", key=f"del_auth_{idx}")
                                        delete_submit = st.button("🔥 영구 삭제 실행", key=f"del_btn_{idx}")
                                        
                                        if delete_submit:
                                            if hash_password(delete_auth) != existing_hash:
                                                st.error("❌ 마스터 비밀번호가 틀려 삭제할 수 없습니다.")
                                            else:
                                                with httpx.Client(headers=headers) as client:
                                                    del_res = client.delete(f"{passwords_url}?id=eq.{item['id']}")
                                                    if del_res.status_code in [200, 204]:
                                                        st.success("🗑️ 계정 정보가 깨끗하게 삭제되었습니다.")
                                                        st.rerun()
                                                    else:
                                                        st.error("삭제 실패")
                else:
                    st.error("데이터 로드 실패")