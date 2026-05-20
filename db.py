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
st.caption("📁 보관함 독립 관리 기능 탑재! 보관함 삭제(안전장치 포함) 및 데이터 일괄 이사가 가능합니다.")
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
        # 💡 [임시 기억 장치 연동] 내 보관함 동적 로드
        # -----------------------------------------------------------------
        if "custom_folders" not in st.session_state:
            st.session_state["custom_folders"] = ["기본 보관함"]

        all_db_data = []
        with httpx.Client(headers=headers) as client:
            res_load = client.get(passwords_url)
            if res_load.status_code == 200:
                all_db_data = res_load.json()
                for item in all_db_data:
                    raw_memo = item.get('memo', '') if item.get('memo') else ""
                    if raw_memo.startswith("[") and "]" in raw_memo:
                        end_idx = raw_memo.find("]")
                        cat_name = raw_memo[1:end_idx].strip()
                        if cat_name and cat_name not in st.session_state["custom_folders"]:
                            st.session_state["custom_folders"].append(cat_name)
        
        category_options = sorted(list(set(st.session_state["custom_folders"])))

        # -----------------------------------------------------------------
        # 🔒 [메인 화면] 3단계 탭 구조 개편 (보관함 독립 분리)
        # -----------------------------------------------------------------
        tab1, tab2, tab3 = st.tabs(["➕ 새 비밀번호 등록", "📁 보관함 관리실", "📋 내 비밀번호 목록"])

        # [TAB 1] 새 비밀번호 등록 (오직 정보 저장에만 집중)
        with tab1:
            st.subheader("🔒 새로운 계정 정보 추가")
            with st.form("add_form", clear_on_submit=True):
                selected_category = st.selectbox("📂 보관할 보관함(폴더) 선택", category_options)
                
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
                                st.success(f"🎉 '{site_name}' 정보가 [{selected_category}] 보관함에 안전하게 저장되었습니다!")
                                st.rerun()

        # [TAB 2] 💡 [신규] 보관함 관리실 (생성, 데이터 이사, 삭제 통합 관리)
        with tab2:
            st.subheader("🛠️ 보관함(폴더) 생성 및 편집")
            
            # 1. 보관함 신규 생성
            with st.expander("➕ 새로운 보관함 만들기", expanded=True):
                col_c1, col_c2 = st.columns([3, 1])
                with col_c1:
                    new_cat_name = st.text_input("새 보관함 이름 입력", placeholder="예: 댕댕쓰업무, 쇼핑몰, 개인금융", key="manage_new_cat")
                with col_c2:
                    st.write("<div style='padding-top:28px;'></div>", unsafe_allow_html=True)
                    if st.button("보관함 개설", use_container_width=True):
                        c_name = new_cat_name.strip()
                        if c_name and c_name not in st.session_state["custom_folders"]:
                            st.session_state["custom_folders"].append(c_name)
                            st.success(f"📁 '{c_name}' 보관함이 생성되었습니다!")
                            st.rerun()
                        elif c_name in st.session_state["custom_folders"]:
                            st.warning("이미 있는 이름입니다.")
            
            st.markdown("---")
            
            # 2. 보관함 일괄 이사 및 데이터 이동 기능
            with st.expander("🔄 보관함 데이터 통째로 이사하기 (내용물 이동)"):
                st.caption("선택한 보관함에 든 모든 계정 정보를 다른 보관함으로 원클릭 일괄 이동시킵니다.")
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    move_from = st.selectbox("출발 보관함 (여기서 꺼내서)", category_options, key="move_from_select")
                with col_m2:
                    move_to = st.selectbox("도착 보관함 (여기로 이동)", category_options, key="move_to_select")
                
                # 해당 출발 보관함에 몇 개 들어있는지 카운트
                from_count = 0
                items_to_move = []
                for item in all_db_data:
                    r_memo = item.get('memo', '') if item.get('memo') else ""
                    if r_memo.startswith(f"[{move_from}]"):
                        from_count += 1
                        items_to_move.append(item)
                
                st.write(f"📦 현재 '{move_from}' 보관함에 저장된 데이터: **{from_count}개**")
                
                if move_from == move_to:
                    st.info("출발지와 도착지가 같습니다. 다른 보관함을 고르세요.")
                else:
                    move_master_auth = st.text_input("인증: 마스터 비밀번호", type="password", key="move_master_auth_input")
                    if st.button("🚚 이사 시작하기", type="primary"):
                        if hash_password(move_master_auth) != existing_hash:
                            st.error("❌ 마스터 비밀번호가 틀렸습니다.")
                        elif from_count == 0:
                            st.warning("이동할 데이터가 없습니다.")
                        else:
                            with st.spinner("데이터 이사 중..."):
                                with httpx.Client(headers=headers) as client:
                                    for item in items_to_move:
                                        old_memo = item['memo']
                                        pure_memo = old_memo.replace(f"[{move_from}]", "").strip()
                                        new_memo = f"[{move_to}] {pure_memo}".strip()
                                        client.patch(f"{passwords_url}?id=eq.{item['id']}", json={"memo": new_memo})
                                st.success(f"🎉 '{move_from}'의 데이터 {from_count}개가 '{move_to}' 보관함으로 모두 이사했습니다!")
                                st.rerun()

            st.markdown("---")

            # 3. 보관함 안전 삭제 기능 (경고 및 재확인 장치 필수 포함)
            with st.expander("🗑️ 보관함 폐쇄 및 삭제 (안전장치 내장)"):
                st.warning("⚠️ 보관함을 삭제하면 그 보관함 안에 들어있는 모든 계정 정보도 함께 영구 삭제됩니다!")
                target_del_cat = st.selectbox("삭제할 보관함 선택", [c for c in category_options if c != "기본 보관함"], key="del_cat_select")
                
                # 해당 보관함 소속 데이터 카운트
                del_count = 0
                items_to_delete = []
                for item in all_db_data:
                    r_memo = item.get('memo', '') if item.get('memo') else ""
                    if r_memo.startswith(f"[{target_del_cat}]"):
                        del_count += 1
                        items_to_delete.append(item)
                
                st.error(f"🚨 선택한 [{target_del_cat}] 보관함 삭제 시, 함께 파기되는 데이터: **{del_count}개**")
                
                # 팝오버를 사용해 한 번 더 확실하게 물어보기
                with st.popover("🔥 보관함 영구 삭제 버튼 활성화"):
                    st.write(f"❗ **진짜 진짜 [{target_del_cat}] 보관함과 내부 데이터 {del_count}개를 전부 삭제하시겠습니까?**")
                    st.write("이 작업은 되돌릴 수 없으며 Supabase 서버에서 즉시 삭제됩니다.")
                    
                    del_master_auth = st.text_input("⚠️ 최종 승인: 마스터 비밀번호 입력", type="password", key="del_cat_master_auth")
                    confirm_checkbox = st.checkbox("네, 위험을 감수하고 모두 삭제하는 것에 동의합니다.")
                    
                    if st.button("💥 예, 최종 삭제합니다", type="primary"):
                        if hash_password(del_master_auth) != existing_hash:
                            st.error("❌ 비밀번호가 틀렸습니다.")
                        elif not confirm_checkbox:
                            st.warning("위의 동의 체크박스에 체크해 주셔야 삭제가 진행됩니다.")
                        else:
                            with st.spinner("서버에서 파기 작업 중..."):
                                with httpx.Client(headers=headers) as client:
                                    # 내부 아이템 전부 삭제
                                    for item in items_to_delete:
                                        client.delete(f"{passwords_url}?id=eq.{item['id']}")
                                # 세션 상태 메모리에서도 삭제
                                if target_del_cat in st.session_state["custom_folders"]:
                                    st.session_state["custom_folders"].remove(target_del_cat)
                            st.success(f"🗑️ [{target_del_cat}] 보관함과 내부 데이터 {del_count}개가 완전히 청소되었습니다!")
                            st.rerun()

        # [TAB 3] 내 비밀번호 목록 조회 (📁 폴더 필터링 및 검색)
        with tab3:
            st.subheader("보관된 비밀번호 목록")
            
            if not all_db_data:
                st.write("아직 저장된 비밀번호가 없습니다.")
            else:
                folder_view = st.radio("📁 열어볼 보관함을 선택하세요", ["📂 전체 보기"] + [f"📁 {cat}" for cat in category_options], horizontal=True)
                
                search_keyword = st.text_input("🔍 이 보관함 내에서 검색 (사이트명, ID, 메모 입력)", "").strip().lower()
                
                filtered_data = []
                for item in all_db_data:
                    raw_memo = item['memo'] if item['memo'] else ""
                    
                    item_category = "기본 보관함"
                    clean_memo = raw_memo
                    
                    if raw_memo.startswith("[") and "]" in raw_memo:
                        end_idx = raw_memo.find("]")
                        item_category = raw_memo[1:end_idx].strip()
                        clean_memo = raw_memo[end_idx+1:].strip()
                    
                    if folder_view != "📂 전체 보기" and f"📁 {item_category}" != folder_view:
                        continue
                        
                    s_name = item['site_name'].lower() if item['site_name'] else ""
                    l_id = item['login_id'].lower() if item['login_id'] else ""
                    s_memo = clean_memo.lower()
                    
                    if search_keyword in s_name or search_keyword in l_id or search_keyword in s_memo:
                        item['parsed_memo'] = clean_memo
                        item['extracted_category'] = item_category
                        filtered_data.append(item)
                
                st.write(f"현재 보관함 내 결과: 총 **{len(filtered_data)}개**")
                st.markdown("---")
                
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
                            with st.popover("✏️ 정보 수정 및 보관함 이동"):
                                edit_category = st.selectbox("📂 이동할 보관함 선택", category_options, index=category_options.index(item['extracted_category']) if item['extracted_category'] in category_options else 0, key=f"edit_cat_{idx}")
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