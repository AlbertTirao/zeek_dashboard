import pandas as pd
import streamlit as st

from services import auth_service


def render(current_username: str):
    st.markdown("## User Management")
    st.caption("Admin-only controls for account provisioning and access state.")

    col_a, _ = st.columns([1, 1])
    with col_a:
        st.markdown("### Create User")
        with st.form("create_user_form", clear_on_submit=True):
            username = st.text_input("Username", placeholder="e.g. analyst1")
            password = st.text_input("Password", type="password", placeholder="At least 8 characters")
            role = st.selectbox("Role", options=["staff", "admin"], index=0)
            submit_create = st.form_submit_button("Create User", use_container_width=True)
        if submit_create:
            try:
                auth_service.create_user(
                    username=username,
                    password=password,
                    role=role,
                    created_by=current_username,
                )
                st.success(f"User '{username.strip().lower()}' created.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    st.markdown("### Accounts")
    table_users = auth_service.list_users()
    if table_users:
        df = pd.DataFrame(table_users)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No accounts available.")
