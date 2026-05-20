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
st.caption("📁 폴더/카테고리 분류 기능이 추가되어 서랍 정리하듯 깔끔하게 관리할 수 있습니다.")
st.markdown("---")

# Supabase 연결 설정 (스트림릿 클라우드 보안 금고 연동)
base_url = "https://tntjmtyomhnlheyskgvi.supabase.co"
try:
    final_key = st.secrets["SUPABASE_KEY"].strip()
except Exception:
    final_key = st.secrets["SUPABASE_KEY"].strip()

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
            if not reg_pw or reg_pw != reg_pw_confirm:
                st.error("비밀번호 입력을 확인해 주세요.")
            else:
                hashed = hash_password(reg_pw)
                with httpx.Client(headers=headers) as client:
                    sub_res = client.post(auth_url, json={"password_hash": hashed})
                    if sub_res.status_code == 201:
                        st.success("🎉 성공적으로 등록되었습니다! 새로고침(F5)을 눌러주세요.")
                        st.rerun()

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
        # 🔒 [메인 화면] 탭 구성
        # -----------------------------------------------------------------
        tab1, tab2 = st.tabs(["➕ 새 비밀번호 등록", "📋 내 비밀번호 목록"])

        # 📂 카테고리(폴더) 기본 목록 구성
        category_options = ["기타/기본", "개인 사이트", "업무/유치원", "금융/은행", "가족/공용"]

        # [TAB 1] 새 비밀번호 등록
        with tab1:
            st.subheader("새로운 계정 정보 추가")
            with st.form("add_form", clear_on_submit=True):
                # 💡 [폴더 기능 추가] 저장할 카테고리 폴더 지정 선택 상자
                selected_category = st.selectbox("📂 보관할 폴더(카테고리) 선택", category_options)
                
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
                        
                        # 💡 기존 구조를 해치지 않기 위해 메모란의 맨 앞에 [카테고리] 머리말을 붙여 숨겨 저장합니다.
                        full_memo = f"[{selected_category}] {memo}".strip()
                        
                        payload = {
                            "site_name": site_name,
                            "site_url": site_url,
                            "login_id": login_id,
                            "encrypted_password": encrypted_pw,
                            "memo": full_memo
                        }
                        with httpx.Client(headers=headers) as client:
                            res = client.post(passwords_url, json=payload)
                            if res.status_code == 201:
                                st.success(f"🎉 '{site_name}' 정보가 {selected_category} 폴더에 안전하게 보관되었습니다!")
                                st.rerun()

        # [TAB 2] 내 비밀번호 목록 조회 (📁 폴더 정렬 및 🔍 통합 검색 탑재)
        with tab2:
            st.subheader("보관된 비밀번호 목록")
            
            with httpx.Client(headers=headers) as client:
                res = client.get(passwords_url)
                if res.status_code == 200:
                    data = res.json()
                    if not data:
                        st.write("아직 저장된 비밀번호가 없습니다.")
                    else:
                        # 💡 [폴더 분류 UI] 라디오 버튼이나 셀렉트박스로 현재 볼 폴더 선택 가능
                        folder_view = st.radio("📁 열어볼 폴더를 선택하세요", ["📂 전체 보기"] + [f"📁 {cat}" for cat in category_options], horizontal=True)
                        
                        # 🔍 검색창 UI 배치
                        search_keyword = st.text_input("🔍 이 폴더 내에서 검색 (사이트명, ID, 메모 입력)", "").strip().lower()
                        
                        filtered_data = []
                        for item in data:
                            raw_memo = item['memo'] if item['memo'] else ""
                            
                            # 데이터에 담긴 카테고리 정보 분석 추출하기
                            item_category = "기타/기본"
                            clean_memo = raw_memo
                            for cat in category_options:
                                if raw_memo.startswith(f"[{cat}]"):
                                    item_category = cat
                                    clean_memo = raw_memo.replace(f"[{cat}]", "").strip() # 화면에는 머리말 떼고 이쁘게 출력
                                    break
                            
                            # 1단계 차단: 내가 선택한 폴더의 데이터가 아니면 패스 (전체 보기일 때는 통과)
                            if folder_view != "📂 전체 보기" and f"📁 {item_category}" != folder_view:
                                continue
                                
                            # 2단계 차단: 검색 키워드 매칭 검사
                            s_name = item['site_name'].lower() if item['site_name'] else ""
                            l_id = item['login_id'].lower() if item['login_id'] else ""
                            s_memo = clean_memo.lower()
                            
                            if search_keyword in s_name or search_keyword in l_id or search_keyword in s_memo:
                                # 수정창 등에서 메모 란이 꼬이지 않도록 파싱된 순수 메모를 보관해 둠
                                item['parsed_memo'] = clean_memo
                                item['extracted_category'] = item_category
                                filtered_data.append(item)
                        
                        st.write(f"현재 폴더 내 결과: 총 **{len(filtered_data)}개**의 계정")
                        st.markdown("---")
                        
                        # 폴더 및 키워드로 걸러진 최종 알짜배기 데이터만 화면에 출력
                        for idx, item in enumerate(filtered_data):
                            with st.expander(f"🌐 [{item['extracted_category']}] {item['site_name']} ({item['login_id']})"):
                                st.write(f"**사이트 주소:** {item['site_url'] if item['site_url'] else '없음'}")
                                st.write(f"**아이디:** `{item['login_id']}`")
                                
                                decrypted_pw = decrypt_password(item['encrypted_password'], input_pw)
                                st.success(f"🔓 **실제 비밀번호:** **{decrypted_pw}**")
                                if item['parsed_memo']:
                                    st.write(f"📝 **메모:** {item['parsed_memo']}")
                                
                                st.markdown("---")
                                col1, col2 = st.columns(2)
                                
                                # [수정하기]
                                with col1:
                                    with st.popover("✏️ 정보 수정하기"):
                                        # 수정할 때도 카테고리 폴더를 변경할 수 있도록 구성
                                        edit_category = st.selectbox("📂 이동할 폴더 선택", category_options, index=category_options.index(item['extracted_category']), key=f"edit_cat_{idx}")
                                        edit_site_name = st.text_input("사이트 이름", value=item['site_name'], key=f"edit_site_{idx}")
                                        edit_site_url = st.text_input("사이트 주소", value=item['site_url'] if item['site_url'] else "", key=f"edit_url_{idx}")
                                        edit_id = st.text_input("아이디", value=item['login_id'], key=f"edit_id_{idx}")
                                        edit_pw = st.text_input("새 비밀번호 (비워두면 기존 유지)", type="password", key=f"edit_pw_{idx}")
                                        edit_memo = st.text_area("메모", value=item['parsed_memo'], key=f"edit_memo_{idx}")
                                        
                                        st.markdown("---")
                                        edit_auth = st.text_input("⚠️ 인증: 마스터 비밀번호 입력", type="password", key=f"edit_auth_{idx}")
                                        edit_submit = st.button("💾 수정사항 저장", key=f"edit_btn_{idx}")
                                        
                                        if edit_submit:
                                            if hash_password(edit_auth) != existing_hash:
                                                st.error("❌ 비밀번호 불일치")
                                            else:
                                                final_encrypted = encrypt_password(edit_pw, edit_auth) if edit_pw else item['encrypted_password']
                                                # 수정 저장 시에도 카테고리 머리말을 이쁘게 말아서 저장
                                                updated_full_memo = f"[{edit_category}] {edit_memo}".strip()
                                                
                                                update_payload = {
                                                    "site_name": edit_site_name,
                                                    "site_url": edit_site_url,
                                                    "login_id": edit_id,
                                                    "encrypted_password": final_encrypted,
                                                    "memo": updated_full_memo
                                                }
                                                with httpx.Client(headers=headers) as client:
                                                    up_res = client.patch(f"{passwords_url}?id=eq.{item['id']}", json=update_payload)
                                                    if up_res.status_code in [200, 204]:
                                                        st.success("🎉 수정 완료!")
                                                        st.rerun()
                                
                                # [삭제하기]
                                with col2:
                                    with st.popover("🗑️ 정보 삭제하기"):
                                        st.write("⚠️ 정말 영구 삭제하시겠습니까?")
                                        delete_auth = st.text_input("⚠️ 인증: 마스터 비밀번호 입력", type="password", key=f"del_auth_{idx}")
                                        delete_submit = st.button("🔥 영구 삭제 실행", key=f"del_btn_{idx}")
                                        
                                        if delete_submit:
                                            if hash_password(delete_auth) != existing_hash:
                                                st.error("❌ 비밀번호 불일치")
                                            else:
                                                with httpx.Client(headers=headers) as client:
                                                    del_res = client.delete(f"{passwords_url}?id=eq.{item['id']}")
                                                    if del_res.status_code in [200, 204]:
                                                        st.success("🗑️ 삭제 완료!")
                                                        st.rerun()
                else:
                    st.error("데이터 로드 실패")