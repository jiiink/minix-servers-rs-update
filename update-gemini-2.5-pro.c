
#include "inc.h"

/*===========================================================================*
 *			      rupdate_clear_upds			     *
 *===========================================================================*/
void rupdate_clear_upds(void)
{
    struct rprocupd *current_rpupd = rupdate.first_rpupd;

    while (current_rpupd != NULL) {
        struct rprocupd *next_rpupd = current_rpupd->next;
        rupdate_upd_clear(current_rpupd);
        current_rpupd = next_rpupd;
    }

    RUPDATE_CLEAR();
}

/*===========================================================================*
 *			       rupdate_add_upd  			     *
 *===========================================================================*/
static int get_update_process_rank(endpoint_t ep)
{
    if (ep == RS_PROC_NR) {
        return 2;
    }
    if (ep == VM_PROC_NR) {
        return 1;
    }
    return 0;
}

void rupdate_add_upd(struct rprocupd* rpupd)
{
    const endpoint_t ep = rpupd->rp->r_pub->endpoint;

    assert(rpupd->next_rpupd == NULL);
    assert(rpupd->prev_rpupd == NULL);

    const int new_rank = get_update_process_rank(ep);
    struct rprocupd *prev_rpupd = rupdate.last_rpupd;
    while (prev_rpupd != NULL && get_update_process_rank(prev_rpupd->rp->r_pub->endpoint) > new_rank) {
        prev_rpupd = prev_rpupd->prev_rpupd;
    }

    struct rprocupd *next_node = (prev_rpupd != NULL) ? prev_rpupd->next_rpupd : rupdate.first_rpupd;

    rpupd->prev_rpupd = prev_rpupd;
    rpupd->next_rpupd = next_node;

    if (next_node != NULL) {
        next_node->prev_rpupd = rpupd;
    } else {
        rupdate.last_rpupd = rpupd;
    }

    if (prev_rpupd != NULL) {
        prev_rpupd->next_rpupd = rpupd;
    } else {
        rupdate.first_rpupd = rpupd;
        rupdate.curr_rpupd = rpupd;
    }

    rupdate.num_rpupds++;

    const int propagated_flags = rpupd->lu_flags &
        (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS | SEF_LU_MULTI);
    if (propagated_flags) {
        for (struct rprocupd *current = rupdate.first_rpupd;
             current != rpupd;
             current = current->next_rpupd) {
            current->lu_flags |= propagated_flags;
            current->init_flags |= propagated_flags;
        }
    }

    if (ep == VM_PROC_NR && rupdate.vm_rpupd == NULL) {
        rupdate.vm_rpupd = rpupd;
    } else if (ep == RS_PROC_NR && rupdate.rs_rpupd == NULL) {
        rupdate.rs_rpupd = rpupd;
    }
}

/*===========================================================================*
 *			  rupdate_set_new_upd_flags  			     *
 *===========================================================================*/
void rupdate_set_new_upd_flags(struct rprocupd* rpupd)
{
    if (!rpupd) {
        return;
    }

    int base_flags = 0;
    if (rupdate.num_rpupds > 0) {
        base_flags |= SEF_LU_MULTI;
    }

    if (rupdate.last_rpupd) {
        base_flags |= rupdate.last_rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS);
    }

    rpupd->lu_flags |= base_flags;
    rpupd->init_flags |= base_flags;

    if (UPD_IS_PREPARING_ONLY(rpupd)) {
        return;
    }

    if (!rpupd->rp || !rpupd->rp->r_pub) {
        return;
    }

    int specific_flags = 0;
    const int endpoint = rpupd->rp->r_pub->endpoint;

    if (endpoint == VM_PROC_NR) {
        specific_flags = SEF_LU_INCLUDES_VM;
    } else if (endpoint == RS_PROC_NR) {
        specific_flags = SEF_LU_INCLUDES_RS;
    }

    rpupd->lu_flags |= specific_flags;
    rpupd->init_flags |= specific_flags;
}

/*===========================================================================*
 *			      rupdate_upd_init  			     *
 *===========================================================================*/
void rupdate_upd_init(struct rprocupd* rpupd, struct rproc *rp)
{
    if (!rpupd) {
        return;
    }

    *rpupd = (struct rprocupd){
        .prepare_state_data_gid = GRANT_INVALID,
        .prepare_state_data = {
            .ipcf_els_gid = GRANT_INVALID,
            .eval_gid = GRANT_INVALID,
        },
        .state_endpoint = NONE,
        .rp = rp,
    };
}

/*===========================================================================*
 *			      rupdate_upd_clear 			     *
 *===========================================================================*/
static void clear_prepare_state_data(struct prepare_state_data_type* data)
{
    if (!data || data->size <= 0) {
        return;
    }

    if (data->ipcf_els_gid != GRANT_INVALID) {
        cpf_revoke(data->ipcf_els_gid);
    }
    if (data->eval_gid != GRANT_INVALID) {
        cpf_revoke(data->eval_gid);
    }

    free(data->ipcf_els);
    free(data->eval_addr);
}

void rupdate_upd_clear(struct rprocupd* rpupd)
{
    if (!rpupd) {
        return;
    }

    if (rpupd->rp && rpupd->rp->r_new_rp) {
        cleanup_service(rpupd->rp->r_new_rp);
    }

    if (rpupd->prepare_state_data_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data_gid);
    }

    clear_prepare_state_data(&rpupd->prepare_state_data);

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
    struct rp_update* moved_upd = &dst_rp->r_upd;
    moved_upd->rp = dst_rp;

    if (src_rp->r_new_rp) {
        assert(!dst_rp->r_new_rp);
        dst_rp->r_new_rp = src_rp->r_new_rp;
        dst_rp->r_new_rp->r_old_rp = dst_rp;
    }

    if (moved_upd->prev_rpupd) {
        moved_upd->prev_rpupd->next_rpupd = moved_upd;
    }
    if (moved_upd->next_rpupd) {
        moved_upd->next_rpupd->prev_rpupd = moved_upd;
    }

    if (rupdate.first_rpupd == &src_rp->r_upd) {
        rupdate.first_rpupd = moved_upd;
    }
    if (rupdate.last_rpupd == &src_rp->r_upd) {
        rupdate.last_rpupd = moved_upd;
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
  if (!rp || !file) {
      return;
  }

  message m = {0};
  m.m_type = RS_LU_PREPARE;
  m.m_rs_update.state = state;

  if (state != SEF_LU_STATE_NULL) {
      struct rprocupd *rpupd = &rp->r_upd;
      rpupd->prepare_tm = getticks();

      if (!UPD_IS_PREPARING_ONLY(rpupd)) {
          assert(rp->r_new_rp);
          rp->r_flags |= RS_UPDATING;
          rp->r_new_rp->r_flags |= RS_UPDATING;
      } else {
          assert(!rp->r_new_rp);
      }

      m.m_rs_update.flags = rpupd->lu_flags;
      m.m_rs_update.state_data_gid = rpupd->prepare_state_data_gid;

      if (rs_verbose) {
          printf("RS: %s being requested to prepare for the %s at %s:%d\n",
              srv_to_string(rp), srv_upd_to_string(rpupd), file, line);
      }
  } else {
      if (rs_verbose) {
          printf("RS: %s being requested to cancel the update at %s:%d\n",
              srv_to_string(rp), file, line);
      }
  }

  const int no_reply = !(rp->r_flags & RS_PREPARE_DONE);
  rs_asynsend(rp, &m, no_reply);
}

/*===========================================================================*
 *				 srv_update				     *
 *===========================================================================*/
int srv_update(endpoint_t src_e, endpoint_t dst_e, int sys_upd_flags)
{
    if (src_e == VM_PROC_NR) {
        if (rs_verbose) {
            printf("RS: executing sys_update(%d, %d)\n", src_e, dst_e);
        }
        int kernel_upd_flags = (sys_upd_flags & SF_VM_ROLLBACK) ? SYS_UPD_ROLLBACK : 0;
        return sys_update(src_e, dst_e, kernel_upd_flags);
    }

    if (!RUPDATE_IS_UPD_VM_MULTI() || RUPDATE_IS_VM_INIT_DONE()) {
        if (rs_verbose) {
            printf("RS: executing vm_update(%d, %d)\n", src_e, dst_e);
        }
        return vm_update(src_e, dst_e, sys_upd_flags);
    }

    if (rs_verbose) {
        printf("RS: skipping srv_update(%d, %d)\n", src_e, dst_e);
    }

    return OK;
}

/*===========================================================================*
 *				update_service				     *
 *===========================================================================*/
int update_service(struct rproc **src_rpp, struct rproc **dst_rpp, int swap_flag, int sys_upd_flags)
{
    int r;
    struct rproc *src_rp = *src_rpp;
    struct rproc *dst_rp = *dst_rpp;
    struct rproc *temp_rp;
    int temp_pid;
    endpoint_t temp_endpoint;

    if (rs_verbose) {
        printf("RS: %s updating into %s\n",
            srv_to_string(src_rp), srv_to_string(dst_rp));
    }

    if (swap_flag == RS_SWAP) {
        r = srv_update(src_rp->r_pub->endpoint, dst_rp->r_pub->endpoint, sys_upd_flags);
        if (r != OK) {
            return r;
        }
    }

    temp_pid = src_rp->r_pid;
    temp_endpoint = src_rp->r_pub->endpoint;

    src_rp->r_pid = dst_rp->r_pid;
    src_rp->r_pub->endpoint = dst_rp->r_pub->endpoint;
    rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)] = src_rp;

    dst_rp->r_pid = temp_pid;
    dst_rp->r_pub->endpoint = temp_endpoint;
    rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)] = dst_rp;

    r = sys_getpriv(&src_rp->r_priv, src_rp->r_pub->endpoint);
    if (r != OK) {
        panic("RS: update: could not update RS copies of priv of src: %d\n", r);
    }

    r = sys_getpriv(&dst_rp->r_priv, dst_rp->r_pub->endpoint);
    if (r != OK) {
        panic("RS: update: could not update RS copies of priv of dst: %d\n", r);
    }

    temp_rp = *src_rpp;
    *src_rpp = *dst_rpp;
    *dst_rpp = temp_rp;

    activate_service(src_rp, dst_rp);

    if (rs_verbose) {
        printf("RS: %s updated into %s\n",
            srv_to_string(dst_rp), srv_to_string(src_rp));
    }

    return OK;
}

/*===========================================================================*
 *			      rollback_service				     *
 *===========================================================================*/
void rollback_service(struct rproc **new_rpp, struct rproc **old_rpp)
{
    int status = OK;
    struct rproc *new_rp = *new_rpp;
    struct rproc *old_rp = *old_rpp;

    if (old_rp->r_pub->endpoint == RS_PROC_NR) {
        endpoint_t me;
        char name[20];
        int priv_flags, init_flags;

        status = sys_whoami(&me, name, sizeof(name), &priv_flags, &init_flags);
        if (status != OK) {
            panic("rollback_service: sys_whoami failed with status %d", status);
        }

        if (me != RS_PROC_NR) {
            status = vm_update(new_rp->r_pub->endpoint, old_rp->r_pub->endpoint, SF_VM_ROLLBACK);
            if (rs_verbose) {
                printf("RS: %s performed rollback\n", srv_to_string(new_rp));
            }
        }

        for (struct rproc *rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
            if (rp->r_flags & RS_ACTIVE) {
                rp->r_check_tm = 0;
            }
        }
    } else {
        int swap_flag = (new_rp->r_flags & RS_INIT_PENDING) ? RS_DONTSWAP : RS_SWAP;
        if (rs_verbose) {
            printf("RS: %s performs rollback\n", srv_to_string(new_rp));
        }

        if (swap_flag == RS_SWAP) {
            sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
        }
        status = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
    }

    if (status != OK) {
        panic("RS: service rollback failed with status %d", status);
    }
}

/*===========================================================================*
 *				update_period				     *
 *===========================================================================*/
void update_period(message *m_ptr)
{
    if (!m_ptr) {
        return;
    }

    struct rprocupd *rpupd = rupdate.curr_rpupd;
    if (!rpupd) {
        return;
    }

    clock_t now = m_ptr->m_notify.timestamp;

    if ((rpupd->prepare_maxtime > 0) && (now - rpupd->prepare_tm > rpupd->prepare_maxtime)) {
        printf("RS: update failed: maximum prepare time reached\n");
        end_update(EINTR, RS_CANCEL);
    }
}

/*===========================================================================*
 *			    start_update_prepare			     *
 *===========================================================================*/
static void prepare_all_components_for_vm_multi_update(void)
{
    for (struct rprocupd *rpupd = rupdate.first_rpupd; rpupd; rpupd = rpupd->rp_next) {
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            continue;
        }

        struct rproc *rp = rpupd->rp;
        struct rproc *new_rp = rp->r_new_rp;
        assert(rp && new_rp);

        rp->r_pub->old_endpoint = rpupd->state_endpoint;
        rp->r_pub->new_endpoint = rp->r_pub->endpoint;

        if (rpupd != rupdate.vm_rpupd && rpupd != rupdate.rs_rpupd) {
            rp->r_pub->sys_flags |= SF_VM_UPDATE;
            if (rpupd->lu_flags & SEF_LU_NOMMAP) {
                rp->r_pub->sys_flags |= SF_VM_NOMMAP;
            }
        }
    }
}

int start_update_prepare(int allow_retries)
{
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
        assert(rupdate.rs_rpupd == rupdate.last_rpupd);
        assert(rupdate.rs_rpupd->rp->r_pub->endpoint == RS_PROC_NR);
        assert(!UPD_IS_PREPARING_ONLY(rupdate.rs_rpupd));
    }
    if (rupdate.vm_rpupd) {
        assert(rupdate.vm_rpupd->rp->r_pub->endpoint == VM_PROC_NR);
        assert(!UPD_IS_PREPARING_ONLY(rupdate.vm_rpupd));
    }

    if (RUPDATE_IS_UPD_VM_MULTI()) {
        prepare_all_components_for_vm_multi_update();
    }

    if (start_update_prepare_next() == NULL) {
        end_update(OK, RS_REPLY);
        return ESRCH;
    }

    return OK;
}

/*===========================================================================*
 *			  start_update_prepare_next			     *
 *===========================================================================*/
static void prepare_vm_for_multicomponent_update(void)
{
    for (struct rprocupd *walk_rpupd = rupdate.first_rpupd; walk_rpupd; walk_rpupd = walk_rpupd->next_rpupd) {
        if (UPD_IS_PREPARING_ONLY(walk_rpupd) || (walk_rpupd == rupdate.vm_rpupd)) {
            continue;
        }

        struct rproc *rp = walk_rpupd->rp;
        struct rproc *new_rp = rp->r_new_rp;
        assert(rp && new_rp);

        if (rs_verbose) {
            printf("RS: preparing VM for %s -> %s\n", srv_to_string(rp), srv_to_string(new_rp));
        }

        vm_prepare(rp->r_pub->new_endpoint, new_rp->r_pub->endpoint, rp->r_pub->sys_flags);
    }
}

struct rprocupd* start_update_prepare_next(void)
{
    struct rprocupd *rpupd = RUPDATE_IS_UPDATING()
                              ? rupdate.curr_rpupd->next_rpupd
                              : rupdate.first_rpupd;

    if (!rpupd) {
        return NULL;
    }

    if (RUPDATE_IS_UPD_VM_MULTI() && rpupd == rupdate.vm_rpupd) {
        prepare_vm_for_multicomponent_update();
    }

    rupdate.flags |= RS_UPDATING;

    do {
        rupdate.curr_rpupd = rpupd;
        request_prepare_update_service(rpupd->rp, rpupd->prepare_state);
        rpupd = rpupd->next_rpupd;
    } while (rpupd && UPD_IS_PREPARING_ONLY(rupdate.curr_rpupd));

    return rupdate.curr_rpupd;
}

/*===========================================================================*
 *				start_update				     *
 *===========================================================================*/
static void cancel_prepare_only_services(void)
{
    struct rprocupd *prev_rpupd, *rpupd;

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
        }
    );
}

static int start_initial_updates(int *init_ready_pending)
{
    struct rprocupd *prev_rpupd, *rpupd;
    int r;

    *init_ready_pending = 0;
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        rupdate.curr_rpupd = rpupd;
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            continue;
        }

        *init_ready_pending = 1;
        r = start_srv_update(rpupd);
        if (r != OK) {
            return r;
        }

        if (!RUPDATE_IS_UPD_VM_MULTI() || rpupd == rupdate.vm_rpupd) {
            r = complete_srv_update(rpupd);
            if (r != OK) {
                return r;
            }
        }
    );

    return OK;
}

static int finalize_vm_multi_update(void)
{
    message m;
    int r;
    int vm_init_result;

    if (rs_verbose) {
        printf("RS: waiting for VM to initialize...\n");
    }

    r = rs_receive_ticks(VM_PROC_NR, &m, NULL, UPD_INIT_MAXTIME(rupdate.vm_rpupd));

    if (r == OK && m.m_type == RS_INIT) {
        vm_init_result = m.m_rs_init.result;
    } else {
        vm_init_result = EINTR;
        m.m_source = VM_PROC_NR;
        m.m_type = RS_INIT;
        m.m_rs_init.result = vm_init_result;
    }

    do_init_ready(&m);

    if (vm_init_result == OK) {
        struct rprocupd *prev_rpupd, *rpupd;

        m.m_type = OK;
        reply(VM_PROC_NR, NULL, &m);

        RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
            if (!UPD_IS_PREPARING_ONLY(rpupd) && rpupd != rupdate.vm_rpupd) {
                r = complete_srv_update(rpupd);
                if (r != OK) {
                    return r;
                }
            }
        );
    }

    return OK;
}

int start_update(void)
{
    int r;
    int init_ready_pending = 0;

    if (rs_verbose) {
        printf("RS: starting a %s-component update process\n",
            RUPDATE_IS_UPD_MULTI() ? "multi" : "single");
    }

    assert(RUPDATE_IS_UPDATING());
    assert(rupdate.num_rpupds > 0);
    assert(rupdate.num_init_ready_pending == 0);
    assert(rupdate.first_rpupd);
    assert(rupdate.last_rpupd);
    assert(rupdate.curr_rpupd == rupdate.last_rpupd);

    rupdate.flags |= RS_INITIALIZING;

    cancel_prepare_only_services();

    r = start_initial_updates(&init_ready_pending);
    if (r != OK) {
        return r;
    }

    if (!init_ready_pending) {
        end_update(OK, 0);
        return OK;
    }

    if (RUPDATE_IS_UPD_VM_MULTI()) {
        return finalize_vm_multi_update();
    }

    return OK;
}

/*===========================================================================*
 *			      start_srv_update				     *
 *===========================================================================*/
int start_srv_update(struct rprocupd *rpupd)
{
    struct rproc *old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp->r_new_rp;

    assert(old_rp && new_rp);

    if (rs_verbose) {
        printf("RS: %s starting the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
    }

    rupdate.num_init_ready_pending++;
    new_rp->r_flags |= (RS_INITIALIZING | RS_INIT_PENDING);

    if (old_rp->r_pub->endpoint == RS_PROC_NR) {
        return OK;
    }

    int sys_upd_flags = 0;
    if (rpupd->lu_flags & SEF_LU_NOMMAP) {
        sys_upd_flags |= SF_VM_NOMMAP;
    }

    const int r = update_service(&old_rp, &new_rp, RS_SWAP, sys_upd_flags);
    if (r != OK) {
        end_update(r, RS_REPLY);
        printf("RS: update failed: error %d\n", r);
        return r;
    }

    return OK;
}

/*===========================================================================*
 *			   complete_srv_update				     *
 *===========================================================================*/
static int complete_rs_self_update(int init_flags, struct rproc *old_rp,
    struct rproc *new_rp)
{
    int r;

    r = init_service(new_rp, SEF_INIT_LU, init_flags);
    if (r != OK) {
        panic("unable to initialize the new RS instance: %d", r);
    }

    if (rs_verbose) {
        printf("RS: %s is the new RS instance we'll yield control to\n",
            srv_to_string(new_rp));
    }

    r = sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_YIELD, NULL);
    if (r != OK) {
        panic("unable to yield control to the new RS instance: %d", r);
    }

    /* If sys_privctl returns, the new RS has failed. Rollback. */
    rollback_service(&new_rp, &old_rp);
    end_update(ERESTART, RS_REPLY);
    printf("RS: update failed: state transfer failed for the new RS instance\n");
    return ERESTART;
}

static int complete_generic_srv_update(int init_flags, struct rproc *old_rp,
    struct rproc *new_rp)
{
    int r;

    r = run_service(new_rp, SEF_INIT_LU, init_flags);
    if (r != OK) {
        rollback_service(&new_rp, &old_rp);
        end_update(r, RS_REPLY);
        printf("RS: update failed: error %d\n", r);
        return r;
    }

    return OK;
}

int complete_srv_update(struct rprocupd *rpupd)
{
    struct rproc *old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp->r_new_rp;

    assert(old_rp && new_rp);

    if (rs_verbose) {
        printf("RS: %s completing the %s\n", srv_to_string(old_rp),
            srv_upd_to_string(rpupd));
    }

    new_rp->r_flags &= ~RS_INIT_PENDING;

    if (old_rp->r_pub->endpoint == RS_PROC_NR) {
        return complete_rs_self_update(rpupd->init_flags, old_rp, new_rp);
    }

    return complete_generic_srv_update(rpupd->init_flags, old_rp, new_rp);
}

/*===========================================================================*
 *			    abort_update_proc				     *
 *===========================================================================*/
int abort_update_proc(int reason)
{
    assert(reason != OK);

    const int is_updating = RUPDATE_IS_UPDATING();

    if (!is_updating && !RUPDATE_IS_UPD_SCHEDULED()) {
        return EINVAL;
    }

    if (rs_verbose) {
        printf("RS: aborting the %s update process prematurely\n",
               is_updating ? "in-progress" : "scheduled");
    }

    if (is_updating) {
        const int end_update_param =
            (rupdate.flags & RS_INITIALIZING) ? RS_REPLY : RS_CANCEL;
        end_update(reason, end_update_param);
    } else {
        rupdate_clear_upds();
    }

    return OK;
}

/*===========================================================================*
 *			    end_update_curr				     *
 *===========================================================================*/
static void end_update_curr(struct rprocupd *rpupd, int result, int reply_flag)
{
    assert(rpupd == rupdate.curr_rpupd);

    struct rproc *old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);

    const bool update_failed = (result != OK);
    const bool is_initializing = SRV_IS_UPDATING_AND_INITIALIZING(new_rp);
    const bool is_not_rs_update = (rpupd != rupdate.rs_rpupd);

    if (update_failed && is_initializing && is_not_rs_update) {
        rollback_service(&new_rp, &old_rp);
    }

    end_srv_update(rpupd, result, reply_flag);
}

/*===========================================================================*
 *			end_update_before_prepare			     *
 *===========================================================================*/
static void end_update_before_prepare(struct rprocupd *rpupd, int result)
{
    assert(result != OK);
    (void)result;

    if (!rpupd || !rpupd->rp) {
        return;
    }

    struct rproc * const new_rp = rpupd->rp->r_new_rp;
    if (new_rp) {
        cleanup_service(new_rp);
    }
}

/*===========================================================================*
 *			 end_update_prepare_done			     *
 *===========================================================================*/
static void handle_update_prepare_failure(struct rprocupd *update_proc, int error_code)
{
    /*
     * The service was blocked for an update that failed to prepare.
     * Unblock the service and clean up the failed update attempt.
     */
    assert(!RUPDATE_IS_INITIALIZING());
    assert(error_code != OK);
    assert(!(update_proc->rp->r_flags & RS_INITIALIZING));

    end_srv_update(update_proc, error_code, RS_REPLY);
}

/*===========================================================================*
 *			 end_update_initializing			     *
 *===========================================================================*/
static void end_update_initializing(struct rprocupd *rpupd, int result)
{
    struct rproc * const old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp->r_new_rp;

    assert(old_rp && new_rp);
    assert(SRV_IS_UPDATING_AND_INITIALIZING(new_rp));

    const int should_rollback = (result != OK) && (rpupd != rupdate.rs_rpupd);

    if (should_rollback) {
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
    short seen_current = 0;
    short is_initializing = RUPDATE_IS_INITIALIZING();

    RUPDATE_REV_ITER(rupdate.last_rpupd, prev_rpupd, rpupd,
        if (UPD_IS_PREPARING_ONLY(rpupd) ||
            (skip_rpupd && rpupd == skip_rpupd) ||
            (only_rpupd && rpupd != only_rpupd)) {
            continue;
        }

        if (rupdate.curr_rpupd == rpupd) {
            end_update_curr(rpupd, result, reply_flag);
            seen_current = 1;
        } else if (!seen_current) {
            if (is_initializing) {
                end_update_prepare_done(rpupd, result);
            } else {
                end_update_before_prepare(rpupd, result);
            }
        } else {
            if (is_initializing) {
                end_update_initializing(rpupd, result);
            } else {
                end_update_prepare_done(rpupd, result);
            }
        }
    );
}

/*===========================================================================*
 *			    end_update_debug				     *
 *===========================================================================*/
static void handle_failed_update_early_exit(int result)
{
    if (result != OK && RUPDATE_IS_RS_INIT_DONE()) {
        if (rs_verbose) {
            printf("RS: update failed, new RS instance will now exit\n");
        }
        exit(1);
    }
}

static void cancel_prepare_only_updates(void)
{
    struct rprocupd *prev_rpupd, *rpupd;

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            if (!RUPDATE_IS_INITIALIZING()) {
                request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
            }
            rpupd->rp->r_flags &= ~RS_PREPARE_DONE;
        }
    );
}

static void end_main_updates(int result, int reply_flag)
{
    end_update_rev_iter(result, reply_flag, rupdate.vm_rpupd, NULL);
    if (rupdate.vm_rpupd) {
        end_update_rev_iter(result, reply_flag, NULL, rupdate.vm_rpupd);
    }
}

static void finalize_and_cleanup_updates(int result)
{
    struct rprocupd *prev_rpupd, *rpupd;

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (prev_rpupd) {
            rupdate_upd_clear(prev_rpupd);
        }
        if (result == OK && !UPD_IS_PREPARING_ONLY(rpupd)) {
            end_srv_init(rpupd->rp);
        }
    );

    late_reply(rupdate.last_rpupd->rp, result);
    rupdate_upd_clear(rupdate.last_rpupd);
}

static void clear_public_update_flags(void)
{
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
        rp->r_pub->sys_flags &= ~(SF_VM_UPDATE | SF_VM_ROLLBACK | SF_VM_NOMMAP);
    }
}

void end_update_debug(char *file, int line, int result, int reply_flag)
{
    assert(RUPDATE_IS_UPDATING());

    if (rs_verbose) {
        printf("RS: %s ending the update: result=%d, reply=%d at %s:%d\n",
            srv_to_string(rupdate.curr_rpupd->rp), result, (reply_flag == RS_REPLY),
            file, line);
    }

    handle_failed_update_early_exit(result);
    cancel_prepare_only_updates();
    end_main_updates(result, reply_flag);
    finalize_and_cleanup_updates(result);

    RUPDATE_CLEAR();
    clear_public_update_flags();
}

/*===========================================================================*
*			      end_srv_update				     *
 *===========================================================================*/
void end_srv_update(struct rprocupd *rpupd, int result, int reply_flag)
{
    struct rproc *old_rp, *new_rp, *exiting_rp, *surviving_rp;
    struct rproc **rps;
    int nr_rps;
    const int update_succeeded = (result == OK);

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);

    if (update_succeeded && new_rp->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) {
        reply_flag = RS_CANCEL;
    }

    if (rs_verbose) {
        printf("RS: ending update from %s to %s with result=%d, reply=%d\n",
            srv_to_string(old_rp), srv_to_string(new_rp), result, (reply_flag == RS_REPLY));
    }

    surviving_rp = update_succeeded ? new_rp : old_rp;
    exiting_rp = update_succeeded ? old_rp : new_rp;

    surviving_rp->r_flags &= ~(RS_INITIALIZING | RS_UPDATING | RS_PREPARE_DONE | RS_INIT_DONE | RS_INIT_PENDING);
    surviving_rp->r_check_tm = 0;
    surviving_rp->r_alive_tm = getticks();

    rpupd->rp = surviving_rp;

    old_rp->r_new_rp = NULL;
    new_rp->r_old_rp = NULL;

    switch (reply_flag) {
        case RS_REPLY: {
            message m;
            m.m_type = result;
            reply(surviving_rp->r_pub->endpoint, surviving_rp, &m);
            break;
        }
        case RS_CANCEL:
            if (!(surviving_rp->r_flags & RS_TERMINATED)) {
                request_prepare_update_service(surviving_rp, SEF_LU_STATE_NULL);
            }
            break;
        default:
            break;
    }

    get_service_instances(exiting_rp, &rps, &nr_rps);
    for (int i = 0; i < nr_rps; i++) {
        struct rproc *current_rp = rps[i];
        if (current_rp == old_rp && (rpupd->lu_flags & SEF_LU_DETACHED)) {
            message m;
            m.m_type = EDEADEPT;
            current_rp->r_flags |= RS_CLEANUP_DETACH;
            reply(current_rp->r_pub->endpoint, current_rp, &m);
        }
        cleanup_service(current_rp);
    }

    if (rs_verbose) {
        printf("RS: %s ended the %s\n", srv_to_string(surviving_rp),
            srv_upd_to_string(rpupd));
    }
}

