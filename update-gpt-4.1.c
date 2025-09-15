
#include "inc.h"

/*===========================================================================*
 *			      rupdate_clear_upds			     *
 *===========================================================================*/
void rupdate_clear_upds(void)
{
    struct rprocupd *prev_rpupd = NULL;
    struct rprocupd *rpupd = rupdate.first_rpupd;

    while (rpupd != NULL) {
        if (prev_rpupd != NULL) {
            rupdate_upd_clear(prev_rpupd);
        }
        prev_rpupd = rpupd;
        rpupd = rpupd->next;
    }

    if (rupdate.last_rpupd != NULL) {
        rupdate_upd_clear(rupdate.last_rpupd);
    }

    RUPDATE_CLEAR();
}

/*===========================================================================*
 *			       rupdate_add_upd  			     *
 *===========================================================================*/
void rupdate_add_upd(struct rprocupd* rpupd)
{
    struct rprocupd *prev_rpupd = NULL;
    endpoint_t ep;
    int lu_flags;

    if (!rpupd || rpupd->next_rpupd || rpupd->prev_rpupd) return;

    ep = rpupd->rp && rpupd->rp->r_pub ? rpupd->rp->r_pub->endpoint : NONE;
    prev_rpupd = rupdate.last_rpupd;
    if (prev_rpupd && ep != RS_PROC_NR &&
        prev_rpupd->rp && prev_rpupd->rp->r_pub &&
        prev_rpupd->rp->r_pub->endpoint == RS_PROC_NR) {
        prev_rpupd = prev_rpupd->prev_rpupd;
    }
    if (prev_rpupd && ep != RS_PROC_NR && ep != VM_PROC_NR &&
        prev_rpupd->rp && prev_rpupd->rp->r_pub &&
        prev_rpupd->rp->r_pub->endpoint == VM_PROC_NR) {
        prev_rpupd = prev_rpupd->prev_rpupd;
    }

    if (!prev_rpupd) {
        rpupd->next_rpupd = rupdate.first_rpupd;
        rpupd->prev_rpupd = NULL;
        rupdate.first_rpupd = rpupd;
        rupdate.curr_rpupd = rpupd;
    } else {
        rpupd->next_rpupd = prev_rpupd->next_rpupd;
        rpupd->prev_rpupd = prev_rpupd;
        prev_rpupd->next_rpupd = rpupd;
    }

    if (rpupd->next_rpupd) {
        rpupd->next_rpupd->prev_rpupd = rpupd;
    } else {
        rupdate.last_rpupd = rpupd;
    }

    rupdate.num_rpupds++;

    lu_flags = rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS | SEF_LU_MULTI);
    if (lu_flags) {
        struct rprocupd *walk_rpupd = rupdate.first_rpupd;
        while (walk_rpupd) {
            walk_rpupd->lu_flags |= lu_flags;
            walk_rpupd->init_flags |= lu_flags;
            walk_rpupd = walk_rpupd->next_rpupd;
        }
    }

    if (!rupdate.vm_rpupd && (lu_flags & SEF_LU_INCLUDES_VM)) {
        rupdate.vm_rpupd = rpupd;
    } else if (!rupdate.rs_rpupd && (lu_flags & SEF_LU_INCLUDES_RS)) {
        rupdate.rs_rpupd = rpupd;
    }
}

/*===========================================================================*
 *			  rupdate_set_new_upd_flags  			     *
 *===========================================================================*/
void rupdate_set_new_upd_flags(struct rprocupd *rpupd)
{
    if (rupdate.num_rpupds > 0) {
        rpupd->lu_flags |= SEF_LU_MULTI;
        rpupd->init_flags |= SEF_LU_MULTI;
    }

    if (rupdate.last_rpupd) {
        int lu_flags = rupdate.last_rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS);
        rpupd->lu_flags |= lu_flags;
        rpupd->init_flags |= lu_flags;
    }

    if (UPD_IS_PREPARING_ONLY(rpupd)) {
        return;
    }

    int endpoint = rpupd->rp && rpupd->rp->r_pub ? rpupd->rp->r_pub->endpoint : -1;

    if (endpoint == VM_PROC_NR) {
        rpupd->lu_flags |= SEF_LU_INCLUDES_VM;
        rpupd->init_flags |= SEF_LU_INCLUDES_VM;
    } else if (endpoint == RS_PROC_NR) {
        rpupd->lu_flags |= SEF_LU_INCLUDES_RS;
        rpupd->init_flags |= SEF_LU_INCLUDES_RS;
    }
}

/*===========================================================================*
 *			      rupdate_upd_init  			     *
 *===========================================================================*/
void rupdate_upd_init(struct rprocupd *rpupd, struct rproc *rp)
{
    if (rpupd == NULL || rp == NULL)
        return;

    memset(rpupd, 0, sizeof(*rpupd));
    rpupd->prepare_state_data_gid = GRANT_INVALID;
    rpupd->prepare_state_data.ipcf_els_gid = GRANT_INVALID;
    rpupd->prepare_state_data.eval_gid = GRANT_INVALID;
    rpupd->state_endpoint = NONE;
    rpupd->rp = rp;
}

/*===========================================================================*
 *			      rupdate_upd_clear 			     *
 *===========================================================================*/
void rupdate_upd_clear(struct rprocupd* rpupd)
{
    if (!rpupd || !rpupd->rp) {
        return;
    }

    if (rpupd->rp->r_new_rp) {
        cleanup_service(rpupd->rp->r_new_rp);
        rpupd->rp->r_new_rp = NULL;
    }

    if (rpupd->prepare_state_data_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data_gid);
        rpupd->prepare_state_data_gid = GRANT_INVALID;
    }

    if (rpupd->prepare_state_data.size > 0) {
        if (rpupd->prepare_state_data.ipcf_els_gid != GRANT_INVALID) {
            cpf_revoke(rpupd->prepare_state_data.ipcf_els_gid);
            rpupd->prepare_state_data.ipcf_els_gid = GRANT_INVALID;
        }
        if (rpupd->prepare_state_data.eval_gid != GRANT_INVALID) {
            cpf_revoke(rpupd->prepare_state_data.eval_gid);
            rpupd->prepare_state_data.eval_gid = GRANT_INVALID;
        }
        if (rpupd->prepare_state_data.ipcf_els) {
            free(rpupd->prepare_state_data.ipcf_els);
            rpupd->prepare_state_data.ipcf_els = NULL;
        }
        if (rpupd->prepare_state_data.eval_addr) {
            free(rpupd->prepare_state_data.eval_addr);
            rpupd->prepare_state_data.eval_addr = NULL;
        }
        rpupd->prepare_state_data.size = 0;
    }

    rupdate_upd_init(rpupd, NULL);
}

/*===========================================================================*
 *			       rupdate_upd_move 			     *
 *===========================================================================*/
void rupdate_upd_move(struct rproc* src_rp, struct rproc* dst_rp)
{
    if (!src_rp || !dst_rp) {
        return;
    }

    dst_rp->r_upd = src_rp->r_upd;
    dst_rp->r_upd.rp = dst_rp;

    if (src_rp->r_new_rp) {
        if (dst_rp->r_new_rp) {
            return;
        }
        dst_rp->r_new_rp = src_rp->r_new_rp;
        if (dst_rp->r_new_rp) {
            dst_rp->r_new_rp->r_old_rp = dst_rp;
        }
    }

    if (dst_rp->r_upd.prev_rpupd) {
        dst_rp->r_upd.prev_rpupd->next_rpupd = &dst_rp->r_upd;
    }
    if (dst_rp->r_upd.next_rpupd) {
        dst_rp->r_upd.next_rpupd->prev_rpupd = &dst_rp->r_upd;
    }
    if (rupdate.first_rpupd == &src_rp->r_upd) {
        rupdate.first_rpupd = &dst_rp->r_upd;
    }
    if (rupdate.last_rpupd == &src_rp->r_upd) {
        rupdate.last_rpupd = &dst_rp->r_upd;
    }

    rupdate_upd_init(&src_rp->r_upd, NULL);
    src_rp->r_new_rp = NULL;
}

/*===========================================================================*
 *		     request_prepare_update_service_debug		     *
 *===========================================================================*/
void request_prepare_update_service_debug(char *file, int line,
  struct rproc *rp, int state)
{
    message m;
    struct rprocpub *rpub = rp->r_pub;
    int no_reply;

    memset(&m, 0, sizeof(m));

    if (state != SEF_LU_STATE_NULL) {
        struct rprocupd *rpupd = &rp->r_upd;
        rpupd->prepare_tm = getticks();
        if (!UPD_IS_PREPARING_ONLY(rpupd)) {
            if (!rp->r_new_rp) {
                fprintf(stderr, "Error: r_new_rp is NULL while not preparing only.\n");
                abort();
            }
            rp->r_flags |= RS_UPDATING;
            rp->r_new_rp->r_flags |= RS_UPDATING;
        } else {
            if (rp->r_new_rp) {
                fprintf(stderr, "Error: r_new_rp should be NULL while preparing only.\n");
                abort();
            }
        }

        m.m_rs_update.flags = rpupd->lu_flags;
        m.m_rs_update.state_data_gid = rpupd->prepare_state_data_gid;

        if (rs_verbose) {
            printf("RS: %s being requested to prepare for the %s at %s:%d\n",
                   srv_to_string(rp),
                   srv_upd_to_string(rpupd),
                   file, line);
        }
    } else {
        if (rs_verbose) {
            printf("RS: %s being requested to cancel the update at %s:%d\n",
                   srv_to_string(rp), file, line);
        }
    }

    m.m_type = RS_LU_PREPARE;
    m.m_rs_update.state = state;
    no_reply = !(rp->r_flags & RS_PREPARE_DONE);

    if (rs_asynsend(rp, &m, no_reply) != 0) {
        fprintf(stderr, "Error: rs_asynsend failed for service %s\n", srv_to_string(rp));
    }
}

/*===========================================================================*
 *				 srv_update				     *
 *===========================================================================*/
int srv_update(endpoint_t src_e, endpoint_t dst_e, int sys_upd_flags)
{
    int r = OK;

    if (src_e == VM_PROC_NR) {
        if (rs_verbose) {
            printf("RS: executing sys_update(%d, %d)\n", src_e, dst_e);
        }
        int sys_flags = (sys_upd_flags & SF_VM_ROLLBACK) ? SYS_UPD_ROLLBACK : 0;
        r = sys_update(src_e, dst_e, sys_flags);
        if (r != OK && rs_verbose) {
            printf("RS: sys_update failed with code %d\n", r);
        }
    } else if (!RUPDATE_IS_UPD_VM_MULTI() || RUPDATE_IS_VM_INIT_DONE()) {
        if (rs_verbose) {
            printf("RS: executing vm_update(%d, %d)\n", src_e, dst_e);
        }
        r = vm_update(src_e, dst_e, sys_upd_flags);
        if (r != OK && rs_verbose) {
            printf("RS: vm_update failed with code %d\n", r);
        }
    } else {
        if (rs_verbose) {
            printf("RS: skipping srv_update(%d, %d)\n", src_e, dst_e);
        }
    }

    return r;
}

/*===========================================================================*
 *				update_service				     *
 *===========================================================================*/
int update_service(struct rproc **src_rpp, struct rproc **dst_rpp, int swap_flag, int sys_upd_flags)
{
    int r;
    struct rproc *src_rp = *src_rpp;
    struct rproc *dst_rp = *dst_rpp;
    struct rprocpub *src_rpub = src_rp->r_pub;
    struct rprocpub *dst_rpub = dst_rp->r_pub;
    int pid;
    endpoint_t endpoint;

    if (rs_verbose) {
        printf("RS: %s updating into %s\n", srv_to_string(src_rp), srv_to_string(dst_rp));
    }

    if (swap_flag == RS_SWAP) {
        r = srv_update(src_rpub->endpoint, dst_rpub->endpoint, sys_upd_flags);
        if (r != OK) {
            return r;
        }
    }

    pid = src_rp->r_pid;
    endpoint = src_rpub->endpoint;

    swap_slot(&src_rp, &dst_rp);

    src_rp->r_pid = dst_rp->r_pid;
    src_rp->r_pub->endpoint = dst_rp->r_pub->endpoint;
    rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)] = src_rp;
    dst_rp->r_pid = pid;
    dst_rp->r_pub->endpoint = endpoint;
    rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)] = dst_rp;

    r = sys_getpriv(&src_rp->r_priv, src_rp->r_pub->endpoint);
    if (r != OK) {
        panic("RS: update: could not update RS copies of priv of src: %d\n", r);
    }
    r = sys_getpriv(&dst_rp->r_priv, dst_rp->r_pub->endpoint);
    if (r != OK) {
        panic("RS: update: could not update RS copies of priv of dst: %d\n", r);
    }

    *src_rpp = src_rp;
    *dst_rpp = dst_rp;

    activate_service(dst_rp, src_rp);

    if (rs_verbose) {
        printf("RS: %s updated into %s\n", srv_to_string(src_rp), srv_to_string(dst_rp));
    }

    return OK;
}

/*===========================================================================*
 *			      rollback_service				     *
 *===========================================================================*/
void rollback_service(struct rproc **new_rpp, struct rproc **old_rpp)
{
    struct rproc *rp;
    int r = OK;

    if ((*old_rpp)->r_pub->endpoint == RS_PROC_NR) {
        endpoint_t me = NONE;
        char name[20] = {0};
        int priv_flags = 0, init_flags = 0;

        r = sys_whoami(&me, name, sizeof(name), &priv_flags, &init_flags);
        if (r != OK) {
            fprintf(stderr, "sys_whoami failed in rollback_service: %d\n", r);
            return;
        }

        if (me != RS_PROC_NR) {
            r = vm_update((*new_rpp)->r_pub->endpoint, (*old_rpp)->r_pub->endpoint, SF_VM_ROLLBACK);
            if (r != OK) {
                fprintf(stderr, "vm_update failed in rollback_service: %d\n", r);
                return;
            }

            if (rs_verbose) {
                const char *srv_str = srv_to_string(*new_rpp);
                printf("RS: %s performed rollback\n", srv_str ? srv_str : "(null)");
            }
        }

        for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
            if (rp->r_flags & RS_ACTIVE) {
                rp->r_check_tm = 0;
            }
        }
    } else {
        int swap_flag = ((*new_rpp)->r_flags & RS_INIT_PENDING) ? RS_DONTSWAP : RS_SWAP;

        if (rs_verbose) {
            const char *srv_str = srv_to_string(*new_rpp);
            printf("RS: %s performs rollback\n", srv_str ? srv_str : "(null)");
        }

        if (swap_flag == RS_SWAP) {
            int privctl_r = sys_privctl((*new_rpp)->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
            if (privctl_r != OK) {
                fprintf(stderr, "sys_privctl failed in rollback_service: %d\n", privctl_r);
                return;
            }
        }

        r = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
        if (r != OK) {
            fprintf(stderr, "update_service failed in rollback_service: %d\n", r);
            return;
        }
    }
}

/*===========================================================================*
 *				update_period				     *
 *===========================================================================*/
void update_period(message *m_ptr)
{
    if (m_ptr == NULL || rupdate.curr_rpupd == NULL) {
        return;
    }

    clock_t now = m_ptr->m_notify.timestamp;
    struct rprocupd *rpupd = rupdate.curr_rpupd;

    if (rpupd->prepare_maxtime > 0 && (now - rpupd->prepare_tm > rpupd->prepare_maxtime)) {
        printf("RS: update failed: maximum prepare time reached\n");
        end_update(EINTR, RS_CANCEL);
    }
}

/*===========================================================================*
 *			    start_update_prepare			     *
 *===========================================================================*/
int start_update_prepare(int allow_retries)
{
    struct rprocupd *rpupd;
    struct rproc *rp, *new_rp;

    if (!RUPDATE_IS_UPD_SCHEDULED()) {
        return EINVAL;
    }
    if (!rs_is_idle()) {
        printf("RS: not idle now, try again\n");
        if (!allow_retries) {
            abort_update_proc(EAGAIN);
        }
        return EAGAIN;
    }

    if (rs_verbose) {
        printf("RS: starting the preparation phase of the update process\n");
    }

    if (rupdate.rs_rpupd) {
        if (rupdate.rs_rpupd != rupdate.last_rpupd ||
            rupdate.rs_rpupd->rp->r_pub->endpoint != RS_PROC_NR ||
            UPD_IS_PREPARING_ONLY(rupdate.rs_rpupd)) {
            abort_update_proc(EINVAL);
            return EINVAL;
        }
    }
    if (rupdate.vm_rpupd) {
        if (rupdate.vm_rpupd->rp->r_pub->endpoint != VM_PROC_NR ||
            UPD_IS_PREPARING_ONLY(rupdate.vm_rpupd)) {
            abort_update_proc(EINVAL);
            return EINVAL;
        }
    }

    if (RUPDATE_IS_UPD_VM_MULTI()) {
        struct rprocupd *prev_rpupd = NULL;
        for (rpupd = rupdate.first_rpupd; rpupd; rpupd = rpupd->next) {
            if (!UPD_IS_PREPARING_ONLY(rpupd)) {
                rp = rpupd->rp;
                new_rp = rp ? rp->r_new_rp : NULL;
                if (!rp || !new_rp) {
                    abort_update_proc(EINVAL);
                    return EINVAL;
                }
                rp->r_pub->old_endpoint = rpupd->state_endpoint;
                rp->r_pub->new_endpoint = rp->r_pub->endpoint;
                if (rpupd != rupdate.vm_rpupd && rpupd != rupdate.rs_rpupd) {
                    rp->r_pub->sys_flags |= SF_VM_UPDATE;
                    if (rpupd->lu_flags & SEF_LU_NOMMAP) {
                        rp->r_pub->sys_flags |= SF_VM_NOMMAP;
                    }
                }
            }
            prev_rpupd = rpupd;
        }
    }

    if (!start_update_prepare_next()) {
        end_update(OK, RS_REPLY);
        return ESRCH;
    }

    return OK;
}


/*===========================================================================*
 *			  start_update_prepare_next			     *
 *===========================================================================*/
struct rprocupd* start_update_prepare_next()
{
    struct rprocupd *rpupd;
    struct rproc *rp, *new_rp;

    if (!RUPDATE_IS_UPDATING()) {
        rpupd = rupdate.first_rpupd;
    } else {
        rpupd = rupdate.curr_rpupd ? rupdate.curr_rpupd->next_rpupd : NULL;
    }
    if (!rpupd) {
        return NULL;
    }

    if (RUPDATE_IS_UPD_VM_MULTI() && rpupd == rupdate.vm_rpupd) {
        struct rprocupd *walk_rpupd = rupdate.first_rpupd;
        while (walk_rpupd) {
            if (!UPD_IS_PREPARING_ONLY(walk_rpupd) &&
                walk_rpupd != rupdate.vm_rpupd) {
                rp = walk_rpupd->rp;
                new_rp = rp ? rp->r_new_rp : NULL;
                if (rp && new_rp && rp->r_pub && new_rp->r_pub) {
                    if (rs_verbose) {
                        printf("RS: preparing VM for %s -> %s\n",
                               srv_to_string(rp),
                               srv_to_string(new_rp));
                    }
                    vm_prepare(rp->r_pub->new_endpoint,
                               new_rp->r_pub->endpoint,
                               rp->r_pub->sys_flags);
                }
            }
            walk_rpupd = walk_rpupd->next_rpupd;
        }
    }

    rupdate.flags |= RS_UPDATING;

    while (rpupd) {
        rupdate.curr_rpupd = rpupd;
        if (rupdate.curr_rpupd->rp) {
            request_prepare_update_service(
                rupdate.curr_rpupd->rp,
                rupdate.curr_rpupd->prepare_state
            );
        }

        if (!UPD_IS_PREPARING_ONLY(rpupd) ||
            !rupdate.curr_rpupd->next_rpupd) {
            break;
        }
        rpupd = rupdate.curr_rpupd->next_rpupd;
    }

    return rpupd;
}

/*===========================================================================*
 *				start_update				     *
 *===========================================================================*/
int start_update()
{
    struct rprocupd *prev_rpupd = NULL, *rpupd = NULL;
    int r = OK, init_ready_pending = 0;

    if (rs_verbose)
        printf("RS: starting a %s-component update process\n",
               RUPDATE_IS_UPD_MULTI() ? "multi" : "single");

    if (!RUPDATE_IS_UPDATING() ||
        rupdate.num_rpupds <= 0 ||
        rupdate.num_init_ready_pending != 0 ||
        !rupdate.first_rpupd ||
        !rupdate.last_rpupd ||
        rupdate.curr_rpupd != rupdate.last_rpupd) {
        return EINVAL;
    }

    rupdate.flags |= RS_INITIALIZING;

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
        }
    );

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        rupdate.curr_rpupd = rpupd;
        if (!UPD_IS_PREPARING_ONLY(rpupd)) {
            init_ready_pending = 1;
            r = start_srv_update(rpupd);
            if (r != OK) return r;
            if (!RUPDATE_IS_UPD_VM_MULTI() || rpupd == rupdate.vm_rpupd) {
                r = complete_srv_update(rpupd);
                if (r != OK) return r;
            }
        }
    );

    if (!init_ready_pending) {
        end_update(OK, 0);
        return OK;
    }

    if (RUPDATE_IS_UPD_VM_MULTI()) {
        message m;
        if (rs_verbose)
            printf("RS: waiting for VM to initialize...\n");
        r = rs_receive_ticks(VM_PROC_NR, &m, NULL, UPD_INIT_MAXTIME(rupdate.vm_rpupd));
        if (r != OK || m.m_type != RS_INIT || m.m_rs_init.result != OK) {
            int res = (r == OK && m.m_type == RS_INIT) ? m.m_rs_init.result : EINTR;
            m.m_source = VM_PROC_NR;
            m.m_type = RS_INIT;
            m.m_rs_init.result = res;
            r = res;
        } else {
            r = OK;
        }
        do_init_ready(&m);
        if (r == OK) {
            m.m_type = OK;
            reply(VM_PROC_NR, NULL, &m);
            RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
                if (!UPD_IS_PREPARING_ONLY(rpupd) && rpupd != rupdate.vm_rpupd) {
                    r = complete_srv_update(rpupd);
                    if (r != OK) return r;
                }
            );
        }
    }

    return OK;
}

/*===========================================================================*
 *			      start_srv_update				     *
 *===========================================================================*/
int start_srv_update(struct rprocupd *rpupd)
{
    struct rproc *old_rp, *new_rp;
    int r, sys_upd_flags = 0;

    if (!rpupd || !rpupd->rp) {
        return EINVAL;
    }

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;

    if (!old_rp || !new_rp) {
        return EINVAL;
    }

    if (rs_verbose) {
        printf("RS: %s starting the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
    }

    rupdate.num_init_ready_pending++;
    new_rp->r_flags |= (RS_INITIALIZING | RS_INIT_PENDING);

    if (rpupd->lu_flags & SEF_LU_NOMMAP) {
        sys_upd_flags |= SF_VM_NOMMAP;
    }

    if (old_rp->r_pub && old_rp->r_pub->endpoint != RS_PROC_NR) {
        r = update_service(&old_rp, &new_rp, RS_SWAP, sys_upd_flags);
        if (r != OK) {
            end_update(r, RS_REPLY);
            printf("RS: update failed: error %d\n", r);
            return r;
        }
    }

    return OK;
}

/*===========================================================================*
 *			   complete_srv_update				     *
 *===========================================================================*/
int complete_srv_update(struct rprocupd *rpupd)
{
    struct rproc *old_rp, *new_rp;
    int r;

    if (!rpupd || !rpupd->rp) {
        return EINVAL;
    }

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;

    if (!old_rp || !new_rp || !old_rp->r_pub) {
        return EINVAL;
    }

    if (rs_verbose) {
        printf("RS: %s completing the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
    }

    new_rp->r_flags &= ~RS_INIT_PENDING;

    if (old_rp->r_pub->endpoint == RS_PROC_NR) {
        r = init_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
        if (r != OK) {
            panic("unable to initialize the new RS instance: %d", r);
            return r;
        }
        if (rs_verbose) {
            printf("RS: %s is the new RS instance we'll yield control to\n", srv_to_string(new_rp));
        }
        r = sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_YIELD, NULL);
        if (r != OK) {
            panic("unable to yield control to the new RS instance: %d", r);
            return r;
        }
        rollback_service(&new_rp, &old_rp);
        end_update(ERESTART, RS_REPLY);
        printf("RS: update failed: state transfer failed for the new RS instance\n");
        return ERESTART;
    }

    r = run_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
    if (r != OK) {
        rollback_service(&new_rp, &old_rp);
        end_update(r, RS_REPLY);
        printf("RS: update failed: error %d\n", r);
        return r;
    }

    return OK;
}

/*===========================================================================*
 *			    abort_update_proc				     *
 *===========================================================================*/
int abort_update_proc(int reason)
{
    int is_updating;

    if (reason == OK) {
        return EINVAL;
    }

    is_updating = RUPDATE_IS_UPDATING();

    if (!is_updating && !RUPDATE_IS_UPD_SCHEDULED()) {
        return EINVAL;
    }

    if (rs_verbose) {
        printf("RS: aborting the %s update process prematurely\n",
               is_updating ? "in-progress" : "scheduled");
    }

    if (!is_updating) {
        rupdate_clear_upds();
        return OK;
    }

    if (rupdate.flags & RS_INITIALIZING) {
        end_update(reason, RS_REPLY);
    } else {
        end_update(reason, RS_CANCEL);
    }

    return OK;
}

/*===========================================================================*
 *			    end_update_curr				     *
 *===========================================================================*/
static void end_update_curr(struct rprocupd *rpupd, int result, int reply_flag)
{
    struct rproc *old_rp;
    struct rproc *new_rp;

    if (rpupd == NULL || rpupd != rupdate.curr_rpupd) {
        return;
    }

    old_rp = rpupd->rp;
    if (!old_rp || !(new_rp = old_rp->r_new_rp)) {
        return;
    }

    if (result != OK &&
        SRV_IS_UPDATING_AND_INITIALIZING(new_rp) &&
        rpupd != rupdate.rs_rpupd)
    {
        rollback_service(&new_rp, &old_rp);
    }

    end_srv_update(rpupd, result, reply_flag);
}

/*===========================================================================*
 *			end_update_before_prepare			     *
 *===========================================================================*/
static void end_update_before_prepare(struct rprocupd *rpupd, int result)
{
    struct rproc *old_rp;
    struct rproc *new_rp;

    if (result == OK || rpupd == NULL)
        return;

    old_rp = rpupd->rp;
    if (old_rp == NULL)
        return;

    new_rp = old_rp->r_new_rp;
    if (new_rp == NULL)
        return;

    cleanup_service(new_rp);
}

/*===========================================================================*
 *			 end_update_prepare_done			     *
 *===========================================================================*/
static void end_update_prepare_done(struct rprocupd *rpupd, int result)
{
    if (RUPDATE_IS_INITIALIZING()) {
        return;
    }
    if (result == OK) {
        return;
    }
    if (rpupd == NULL || rpupd->rp == NULL) {
        return;
    }
    if (rpupd->rp->r_flags & RS_INITIALIZING) {
        return;
    }

    end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			 end_update_initializing			     *
 *===========================================================================*/
static void end_update_initializing(struct rprocupd *rpupd, int result)
{
    if (!rpupd) {
        return;
    }

    struct rproc *old_rp = rpupd->rp;
    if (!old_rp) {
        return;
    }

    struct rproc *new_rp = old_rp->r_new_rp;
    if (!new_rp) {
        return;
    }

    if (!SRV_IS_UPDATING_AND_INITIALIZING(new_rp)) {
        return;
    }

    if (result != OK && rpupd != rupdate.rs_rpupd) {
        rollback_service(&new_rp, &old_rp);
    }

    end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			    end_update_rev_iter				     *
 *===========================================================================*/
static void end_update_rev_iter(int result, int reply_flag,
    struct rprocupd *skip_rpupd, struct rprocupd *only_rpupd)
{
    struct rprocupd *prev_rpupd, *rpupd;
    int is_after_curr = 1;

    RUPDATE_REV_ITER(rupdate.last_rpupd, prev_rpupd, rpupd,
        int is_curr = (rupdate.curr_rpupd == rpupd);
        is_after_curr = is_after_curr && !is_curr;

        if (UPD_IS_PREPARING_ONLY(rpupd))
            continue;

        if ((skip_rpupd && rpupd == skip_rpupd) || (only_rpupd && rpupd != only_rpupd))
            continue;

        int is_before_curr = !is_curr && !is_after_curr;
        int is_before_prepare, is_prepare_done, is_initializing;

        if (RUPDATE_IS_INITIALIZING()) {
            is_before_prepare = 0;
            is_prepare_done = is_after_curr;
            is_initializing = is_before_curr;
        } else {
            is_before_prepare = is_after_curr;
            is_prepare_done = is_before_curr;
            is_initializing = 0;
        }

        if (is_curr) {
            end_update_curr(rpupd, result, reply_flag);
        } else if (is_before_prepare) {
            end_update_before_prepare(rpupd, result);
        } else if (is_prepare_done) {
            end_update_prepare_done(rpupd, result);
        } else if (is_initializing) {
            end_update_initializing(rpupd, result);
        }
    );
}

/*===========================================================================*
 *			    end_update_debug				     *
 *===========================================================================*/
void end_update_debug(char *file, int line, int result, int reply_flag)
{
    struct rprocupd *prev_rpupd = NULL, *rpupd = NULL;
    struct rproc *rp = NULL, *new_rp = NULL;
    int slot_nr = 0;

    assert(RUPDATE_IS_UPDATING());

    if (rs_verbose)
        printf("RS: %s ending the update: result=%d, reply=%d at %s:%d\n",
               srv_to_string(rupdate.curr_rpupd && rupdate.curr_rpupd->rp ? rupdate.curr_rpupd->rp : NULL),
               result, (reply_flag == RS_REPLY), file, line);

    if (result != OK && RUPDATE_IS_RS_INIT_DONE()) {
        if (rs_verbose)
            printf("RS: update failed, new RS instance will now exit\n");
        exit(1);
    }

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            if (!RUPDATE_IS_INITIALIZING()) {
                request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
            }
            if (rpupd->rp)
                rpupd->rp->r_flags &= ~RS_PREPARE_DONE;
        }
    );

    end_update_rev_iter(result, reply_flag, rupdate.vm_rpupd, NULL);
    if (rupdate.vm_rpupd) {
        end_update_rev_iter(result, reply_flag, NULL, rupdate.vm_rpupd);
    }

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (prev_rpupd) {
            rupdate_upd_clear(prev_rpupd);
        }
        if (result == OK && !UPD_IS_PREPARING_ONLY(rpupd) && rpupd->rp) {
            new_rp = rpupd->rp;
            end_srv_init(new_rp);
        }
    );

    if (rupdate.last_rpupd && rupdate.last_rpupd->rp) {
        late_reply(rupdate.last_rpupd->rp, result);
    }
    if (rupdate.last_rpupd) {
        rupdate_upd_clear(rupdate.last_rpupd);
    }
    RUPDATE_CLEAR();

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        if (rp->r_pub) {
            rp->r_pub->old_endpoint = NONE;
            rp->r_pub->new_endpoint = NONE;
            rp->r_pub->sys_flags &= ~(SF_VM_UPDATE | SF_VM_ROLLBACK | SF_VM_NOMMAP);
        }
    }
}

/*===========================================================================*
*			      end_srv_update				     *
 *===========================================================================*/
void end_srv_update(struct rprocupd *rpupd, int result, int reply_flag)
{
    struct rproc *old_rp = NULL, *new_rp = NULL, *exiting_rp = NULL, *surviving_rp = NULL;
    struct rproc **rps = NULL;
    int nr_rps = 0, i = 0;

    if (!rpupd)
        return;

    old_rp = rpupd->rp;
    if (!old_rp)
        return;

    new_rp = old_rp->r_new_rp;
    if (!new_rp)
        return;

    if (result == OK && new_rp->r_pub && new_rp->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) {
        reply_flag = RS_CANCEL;
    }

    if (rs_verbose) {
        printf("RS: ending update from %s to %s with result=%d, reply=%d\n",
            srv_to_string(old_rp), srv_to_string(new_rp), result, (reply_flag==RS_REPLY));
    }

    if (result == OK) {
        surviving_rp = new_rp;
        exiting_rp = old_rp;
    } else {
        surviving_rp = old_rp;
        exiting_rp = new_rp;
    }

    surviving_rp->r_flags &= ~RS_INITIALIZING;
    surviving_rp->r_check_tm = 0;
    surviving_rp->r_alive_tm = getticks();

    rpupd->rp = surviving_rp;

    old_rp->r_new_rp = NULL;
    new_rp->r_old_rp = NULL;

    surviving_rp->r_flags &= ~(RS_UPDATING|RS_PREPARE_DONE|RS_INIT_DONE|RS_INIT_PENDING);

    if (reply_flag == RS_REPLY) {
        message m;
        m.m_type = result;
        if (surviving_rp->r_pub)
            reply(surviving_rp->r_pub->endpoint, surviving_rp, &m);
    } else if (reply_flag == RS_CANCEL) {
        if (!(surviving_rp->r_flags & RS_TERMINATED)) {
            request_prepare_update_service(surviving_rp, SEF_LU_STATE_NULL);
        }
    }

    get_service_instances(exiting_rp, &rps, &nr_rps);
    for (i = 0; i < nr_rps; i++) {
        if (!rps[i])
            continue;
        if (rps[i] == old_rp && (rpupd->lu_flags & SEF_LU_DETACHED)) {
            message m;
            m.m_type = EDEADEPT;
            rps[i]->r_flags |= RS_CLEANUP_DETACH;
            cleanup_service(rps[i]);
            if (rps[i]->r_pub)
                reply(rps[i]->r_pub->endpoint, rps[i], &m);
        } else {
            cleanup_service(rps[i]);
        }
    }

    if (rps)
        free(rps);

    if (rs_verbose)
        printf("RS: %s ended the %s\n", srv_to_string(surviving_rp),
            srv_upd_to_string(rpupd));
}

