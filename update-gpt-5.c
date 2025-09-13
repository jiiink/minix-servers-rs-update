
#include "inc.h"

/*===========================================================================*
 *			      rupdate_clear_upds			     *
 *===========================================================================*/
void rupdate_clear_upds(void)
{
    struct rprocupd *prev_rpupd = NULL;
    struct rprocupd *rpupd = NULL;

    if (rupdate.first_rpupd == NULL) {
        RUPDATE_CLEAR();
        return;
    }

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (prev_rpupd != NULL) {
            rupdate_upd_clear(prev_rpupd);
        }
    );

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
    struct rprocupd *prev, *walk, *next;
    endpoint_t ep;
    int lu_flags;

    if (rpupd == NULL || rpupd->rp == NULL || rpupd->rp->r_pub == NULL)
        return;

    ep = rpupd->rp->r_pub->endpoint;

    assert(rpupd->next_rpupd == NULL);
    assert(rpupd->prev_rpupd == NULL);
    if (rpupd->next_rpupd != NULL || rpupd->prev_rpupd != NULL)
        return;

    prev = rupdate.last_rpupd;

    if (prev != NULL && ep != RS_PROC_NR) {
        if (prev->rp && prev->rp->r_pub &&
            prev->rp->r_pub->endpoint == RS_PROC_NR) {
            prev = prev->prev_rpupd;
        }
    }

    if (prev != NULL && ep != RS_PROC_NR && ep != VM_PROC_NR) {
        if (prev->rp && prev->rp->r_pub &&
            prev->rp->r_pub->endpoint == VM_PROC_NR) {
            prev = prev->prev_rpupd;
        }
    }

    if (prev == NULL) {
        rpupd->prev_rpupd = NULL;
        rpupd->next_rpupd = rupdate.first_rpupd;
        rupdate.first_rpupd = rpupd;
        rupdate.curr_rpupd = rpupd;
    } else {
        rpupd->prev_rpupd = prev;
        rpupd->next_rpupd = prev->next_rpupd;
        prev->next_rpupd = rpupd;
    }

    next = rpupd->next_rpupd;
    if (next != NULL) {
        next->prev_rpupd = rpupd;
    } else {
        rupdate.last_rpupd = rpupd;
    }

    rupdate.num_rpupds++;

    lu_flags = rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS | SEF_LU_MULTI);
    if (lu_flags != 0) {
        for (walk = rupdate.first_rpupd; walk != NULL; walk = walk->next_rpupd) {
            walk->lu_flags |= lu_flags;
            walk->init_flags |= lu_flags;
        }
    }

    if (rupdate.vm_rpupd == NULL && (lu_flags & SEF_LU_INCLUDES_VM)) {
        rupdate.vm_rpupd = rpupd;
    } else if (rupdate.rs_rpupd == NULL && (lu_flags & SEF_LU_INCLUDES_RS)) {
        rupdate.rs_rpupd = rpupd;
    }
}

/*===========================================================================*
 *			  rupdate_set_new_upd_flags  			     *
 *===========================================================================*/
void rupdate_set_new_upd_flags(struct rprocupd* rpupd)
{
    int flags_to_set = 0;

    if (!rpupd) return;

    if (rupdate.num_rpupds > 0) {
        flags_to_set |= SEF_LU_MULTI;
    }

    if (rupdate.last_rpupd) {
        int lu_flags = rupdate.last_rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS);
        flags_to_set |= lu_flags;
    }

    if (!UPD_IS_PREPARING_ONLY(rpupd)) {
        int endpoint = 0;
        if (rpupd->rp && rpupd->rp->r_pub) {
            endpoint = rpupd->rp->r_pub->endpoint;
        }

        if (endpoint == VM_PROC_NR) {
            flags_to_set |= SEF_LU_INCLUDES_VM;
        } else if (endpoint == RS_PROC_NR) {
            flags_to_set |= SEF_LU_INCLUDES_RS;
        }
    }

    rpupd->lu_flags |= flags_to_set;
    rpupd->init_flags |= flags_to_set;
}

/*===========================================================================*
 *			      rupdate_upd_init  			     *
 *===========================================================================*/
void rupdate_upd_init(struct rprocupd* rpupd, struct rproc *rp)
{
    if (rpupd == NULL) {
        return;
    }

    *rpupd = (struct rprocupd){
        .prepare_state_data_gid = GRANT_INVALID,
        .prepare_state_data = {
            .ipcf_els_gid = GRANT_INVALID,
            .eval_gid = GRANT_INVALID
        },
        .state_endpoint = NONE,
        .rp = rp
    };
}

/*===========================================================================*
 *			      rupdate_upd_clear 			     *
 *===========================================================================*/
void rupdate_upd_clear(struct rprocupd* rpupd)
{
    if (!rpupd) return;

    if (rpupd->rp && rpupd->rp->r_new_rp) {
        cleanup_service(rpupd->rp->r_new_rp);
    }

    if (rpupd->prepare_state_data_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data_gid);
    }

    if (rpupd->prepare_state_data.size > 0) {
        if (rpupd->prepare_state_data.ipcf_els_gid != GRANT_INVALID) {
            cpf_revoke(rpupd->prepare_state_data.ipcf_els_gid);
        }
        if (rpupd->prepare_state_data.eval_gid != GRANT_INVALID) {
            cpf_revoke(rpupd->prepare_state_data.eval_gid);
        }
        free(rpupd->prepare_state_data.ipcf_els);
        free(rpupd->prepare_state_data.eval_addr);
    }

    rupdate_upd_init(rpupd, NULL);
}

/*===========================================================================*
 *			       rupdate_upd_move 			     *
 *===========================================================================*/
void rupdate_upd_move(struct rproc* src_rp, struct rproc* dst_rp)
{
  if (src_rp == NULL || dst_rp == NULL || src_rp == dst_rp) {
    return;
  }

  dst_rp->r_upd = src_rp->r_upd;
  dst_rp->r_upd.rp = dst_rp;

  if (src_rp->r_new_rp) {
    assert(!dst_rp->r_new_rp);
    dst_rp->r_new_rp = src_rp->r_new_rp;
    dst_rp->r_new_rp->r_old_rp = dst_rp;
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
  int no_reply;

  if (rp == NULL) {
    return;
  }

  memset(&m, 0, sizeof(m));

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

  m.m_type = RS_LU_PREPARE;
  m.m_rs_update.state = state;
  no_reply = !(rp->r_flags & RS_PREPARE_DONE);
  (void) rs_asynsend(rp, &m, no_reply);
}

/*===========================================================================*
 *				 srv_update				     *
 *===========================================================================*/
int srv_update(endpoint_t src_e, endpoint_t dst_e, int sys_upd_flags)
{
    int r = OK;
    const int is_vm_proc = (src_e == VM_PROC_NR);
    const int is_upd_vm_multi = RUPDATE_IS_UPD_VM_MULTI();
    const int is_vm_init_done = RUPDATE_IS_VM_INIT_DONE();

    if (is_vm_proc) {
        if (rs_verbose) {
            printf("RS: executing sys_update(%d, %d)\n", (int)src_e, (int)dst_e);
        }
        {
            const int kernel_flags = (sys_upd_flags & SF_VM_ROLLBACK) ? SYS_UPD_ROLLBACK : 0;
            return sys_update(src_e, dst_e, kernel_flags);
        }
    }

    if (!is_upd_vm_multi || is_vm_init_done) {
        if (rs_verbose) {
            printf("RS: executing vm_update(%d, %d)\n", (int)src_e, (int)dst_e);
        }
        return vm_update(src_e, dst_e, sys_upd_flags);
    }

    if (rs_verbose) {
        printf("RS: skipping srv_update(%d, %d)\n", (int)src_e, (int)dst_e);
    }

    return r;
}

/*===========================================================================*
 *				update_service				     *
 *===========================================================================*/
int update_service(struct rproc **src_rpp, struct rproc **dst_rpp, int swap_flag, int sys_upd_flags)
{
  int r;
  struct rproc *src_rp;
  struct rproc *dst_rp;
  int pid;
  endpoint_t src_ep;
  endpoint_t dst_ep;

  if (src_rpp == NULL || dst_rpp == NULL || *src_rpp == NULL || *dst_rpp == NULL)
    return EINVAL;

  src_rp = *src_rpp;
  dst_rp = *dst_rpp;

  if (src_rp->r_pub == NULL || dst_rp->r_pub == NULL)
    return EINVAL;

  src_ep = src_rp->r_pub->endpoint;
  dst_ep = dst_rp->r_pub->endpoint;

  if (rs_verbose)
    printf("RS: %s updating into %s\n", srv_to_string(src_rp), srv_to_string(dst_rp));

  if (swap_flag == RS_SWAP) {
    r = srv_update(src_ep, dst_ep, sys_upd_flags);
    if (r != OK) return r;
  }

  pid = src_rp->r_pid;

  swap_slot(&src_rp, &dst_rp);

  src_rp->r_pid = dst_rp->r_pid;
  src_rp->r_pub->endpoint = dst_rp->r_pub->endpoint;
  rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)] = src_rp;

  dst_rp->r_pid = pid;
  dst_rp->r_pub->endpoint = src_ep;
  rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)] = dst_rp;

  r = sys_getpriv(&src_rp->r_priv, src_rp->r_pub->endpoint);
  if (r != OK) panic("RS: update: could not update RS copies of priv of src: %d\n", r);
  r = sys_getpriv(&dst_rp->r_priv, dst_rp->r_pub->endpoint);
  if (r != OK) panic("RS: update: could not update RS copies of priv of dst: %d\n", r);

  *src_rpp = src_rp;
  *dst_rpp = dst_rp;

  activate_service(dst_rp, src_rp);

  if (rs_verbose)
    printf("RS: %s updated into %s\n", srv_to_string(src_rp), srv_to_string(dst_rp));

  return OK;
}

/*===========================================================================*
 *			      rollback_service				     *
 *===========================================================================*/
void rollback_service(struct rproc **new_rpp, struct rproc **old_rpp)
{
    if (!new_rpp || !old_rpp || !*new_rpp || !*old_rpp || !(*new_rpp)->r_pub || !(*old_rpp)->r_pub) {
        return;
    }

    struct rproc *new_rp = *new_rpp;
    struct rproc *old_rp = *old_rpp;
    int r = OK;

    if (old_rp->r_pub->endpoint == RS_PROC_NR) {
        endpoint_t me = NONE;
        char name[20];
        int priv_flags = 0, init_flags = 0;

        r = sys_whoami(&me, name, sizeof(name), &priv_flags, &init_flags);
        if (r != OK) {
            return;
        }

        if (me != RS_PROC_NR) {
            r = vm_update(new_rp->r_pub->endpoint, old_rp->r_pub->endpoint, SF_VM_ROLLBACK);
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
            (void)sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
        }

        r = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
    }

    assert(r == OK);
}

/*===========================================================================*
 *				update_period				     *
 *===========================================================================*/
void update_period(message *m_ptr)
{
  struct rprocupd *rpupd;
  clock_t now;
  clock_t diff;

  if (m_ptr == NULL) {
    return;
  }

  rpupd = rupdate.curr_rpupd;
  if (rpupd == NULL) {
    return;
  }

  if (rpupd->prepare_maxtime <= 0) {
    return;
  }

  now = m_ptr->m_notify.timestamp;

  if (now > rpupd->prepare_tm) {
    diff = now - rpupd->prepare_tm;
  } else {
    diff = 0;
  }

  if (diff > rpupd->prepare_maxtime) {
    printf("RS: update failed: maximum prepare time reached\n");
    end_update(EINTR, RS_CANCEL);
  }
}

/*===========================================================================*
 *			    start_update_prepare			     *
 *===========================================================================*/
int start_update_prepare(int allow_retries)
{
  struct rprocupd *prev_rpupd = NULL, *rpupd = NULL;
  struct rproc *rp = NULL;

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
      RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
          if (!UPD_IS_PREPARING_ONLY(rpupd)) {
              rp = rpupd->rp;
              assert(rp && rp->r_new_rp);
              assert(rp->r_pub);

              rp->r_pub->old_endpoint = rpupd->state_endpoint;
              rp->r_pub->new_endpoint = rp->r_pub->endpoint;

              if (rpupd != rupdate.vm_rpupd && rpupd != rupdate.rs_rpupd) {
                  rp->r_pub->sys_flags |= SF_VM_UPDATE;
                  if (rpupd->lu_flags & SEF_LU_NOMMAP) {
                      rp->r_pub->sys_flags |= SF_VM_NOMMAP;
                  }
              }
          }
      );
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
struct rprocupd* start_update_prepare_next()
{
    struct rprocupd *rpupd, *prev_rpupd, *walk_rpupd;
    struct rproc *rp, *new_rp;

    rpupd = RUPDATE_IS_UPDATING() ? rupdate.curr_rpupd->next_rpupd
                                  : rupdate.first_rpupd;
    if (!rpupd) {
        return NULL;
    }

    if (RUPDATE_IS_UPD_VM_MULTI() && rpupd == rupdate.vm_rpupd) {
        RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, walk_rpupd,
            if (UPD_IS_PREPARING_ONLY(walk_rpupd))
                continue;
            if (walk_rpupd == rupdate.vm_rpupd)
                continue;
            rp = walk_rpupd->rp;
            new_rp = rp->r_new_rp;
            assert(rp && new_rp);
            if (rs_verbose)
                printf("RS: preparing VM for %s -> %s\n",
                    srv_to_string(rp), srv_to_string(new_rp));
            (void)vm_prepare(rp->r_pub->new_endpoint, new_rp->r_pub->endpoint,
                rp->r_pub->sys_flags);
        );
    }

    rupdate.flags |= RS_UPDATING;

    for (;;) {
        rupdate.curr_rpupd = rpupd;
        request_prepare_update_service(rupdate.curr_rpupd->rp,
            rupdate.curr_rpupd->prepare_state);
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
  struct rprocupd *prev_rpupd, *rpupd;
  int r, init_ready_pending = 0;
  int vm_multi;

  if (rs_verbose)
    printf("RS: starting a %s-component update process\n",
        RUPDATE_IS_UPD_MULTI() ? "multi" : "single");

  assert(RUPDATE_IS_UPDATING());
  assert(rupdate.num_rpupds > 0);
  assert(rupdate.num_init_ready_pending == 0);
  assert(rupdate.first_rpupd);
  assert(rupdate.last_rpupd);
  assert(rupdate.curr_rpupd == rupdate.last_rpupd);

  rupdate.flags |= RS_INITIALIZING;

  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
    if (UPD_IS_PREPARING_ONLY(rpupd)) {
      request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
    }
  );

  vm_multi = RUPDATE_IS_UPD_VM_MULTI();

  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
    rupdate.curr_rpupd = rpupd;
    if (UPD_IS_PREPARING_ONLY(rpupd)) {
      continue;
    }
    init_ready_pending = 1;
    r = start_srv_update(rpupd);
    if (r != OK) {
      return r;
    }
    if (!vm_multi || rpupd == rupdate.vm_rpupd) {
      r = complete_srv_update(rpupd);
      if (r != OK) {
        return r;
      }
    }
  );

  if (!init_ready_pending) {
    end_update(OK, 0);
    return OK;
  }

  if (vm_multi) {
    message m;
    if (rs_verbose)
      printf("RS: waiting for VM to initialize...\n");

    r = rs_receive_ticks(VM_PROC_NR, &m, NULL, UPD_INIT_MAXTIME(rupdate.vm_rpupd));

    if (r != OK || m.m_type != RS_INIT || m.m_rs_init.result != OK) {
      r = (r == OK && m.m_type == RS_INIT) ? m.m_rs_init.result : EINTR;
      m.m_source = VM_PROC_NR;
      m.m_type = RS_INIT;
      m.m_rs_init.result = r;
    }

    do_init_ready(&m);

    if (r == OK) {
      message reply_msg;
      memset(&reply_msg, 0, sizeof(reply_msg));
      reply_msg.m_type = OK;
      reply(VM_PROC_NR, NULL, &reply_msg);

      RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (!UPD_IS_PREPARING_ONLY(rpupd) && rpupd != rupdate.vm_rpupd) {
          r = complete_srv_update(rpupd);
          if (r != OK) {
            return r;
          }
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
    int r;
    int sys_upd_flags;

    if (rpupd == NULL || rpupd->rp == NULL || rpupd->rp->r_new_rp == NULL || rpupd->rp->r_pub == NULL) {
        return EINVAL;
    }

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;

    if (rs_verbose) {
        printf("RS: %s starting the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
    }

    rupdate.num_init_ready_pending++;
    new_rp->r_flags |= (RS_INITIALIZING | RS_INIT_PENDING);

    sys_upd_flags = (rpupd->lu_flags & SEF_LU_NOMMAP) ? SF_VM_NOMMAP : 0;

    if (old_rp->r_pub->endpoint != RS_PROC_NR) {
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
  int r, old_ep;

  if (!rpupd || !rpupd->rp) {
    return EINVAL;
  }

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  if (!new_rp || !old_rp->r_pub || !new_rp->r_pub) {
    return EINVAL;
  }

  if (rs_verbose) {
    printf("RS: %s completing the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
  }

  new_rp->r_flags &= ~RS_INIT_PENDING;

  old_ep = old_rp->r_pub->endpoint;
  if (old_ep == RS_PROC_NR) {
    r = init_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
    if (r != OK) {
      panic("unable to initialize the new RS instance: %d", r);
    }
    if (rs_verbose) {
      printf("RS: %s is the new RS instance we'll yield control to\n", srv_to_string(new_rp));
    }
    r = sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_YIELD, NULL);
    if (r != OK) {
      panic("unable to yield control to the new RS instance: %d", r);
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
  int updating = RUPDATE_IS_UPDATING();
  int scheduled = RUPDATE_IS_UPD_SCHEDULED();

  assert(reason != OK);

  if(!updating && !scheduled) return EINVAL;

  if(rs_verbose) {
    const char *phase = updating ? "in-progress" : "scheduled";
    printf("RS: aborting the %s update process prematurely\n", phase);
  }

  if(!updating) {
    rupdate_clear_upds();
    return OK;
  }

  end_update(reason, (rupdate.flags & RS_INITIALIZING) ? RS_REPLY : RS_CANCEL);
  return OK;
}

/*===========================================================================*
 *			    end_update_curr				     *
 *===========================================================================*/
static void end_update_curr(struct rprocupd *rpupd, int result, int reply_flag)
{
    struct rproc *old_rp = NULL;
    struct rproc *new_rp = NULL;

    if (rpupd == NULL) {
        return;
    }

    assert(rpupd == rupdate.curr_rpupd);

    old_rp = rpupd->rp;
    new_rp = (old_rp != NULL) ? old_rp->r_new_rp : NULL;

    assert(old_rp && new_rp);

    if (old_rp == NULL || new_rp == NULL) {
        end_srv_update(rpupd, result, reply_flag);
        return;
    }

    if (result != OK &&
        rpupd != rupdate.rs_rpupd &&
        SRV_IS_UPDATING_AND_INITIALIZING(new_rp)) {
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

    if (rpupd == NULL || result == OK) {
        return;
    }

    old_rp = rpupd->rp;
    if (old_rp == NULL) {
        return;
    }

    new_rp = old_rp->r_new_rp;
    if (new_rp == NULL) {
        return;
    }

    cleanup_service(new_rp);
}

/*===========================================================================*
 *			 end_update_prepare_done			     *
 *===========================================================================*/
static void end_update_prepare_done(struct rprocupd *rpupd, int result)
{
    if (rpupd == NULL || rpupd->rp == NULL) {
        return;
    }

    assert(!RUPDATE_IS_INITIALIZING());
    assert(result != OK);
    assert(!(rpupd->rp->r_flags & RS_INITIALIZING));

    end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			 end_update_initializing			     *
 *===========================================================================*/
static void end_update_initializing(struct rprocupd *rpupd, int result)
{
    struct rproc *old_rp;
    struct rproc *new_rp;

    if (rpupd == NULL || rpupd->rp == NULL) {
        end_srv_update(rpupd, result, RS_REPLY);
        return;
    }

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;

    if (new_rp == NULL || !SRV_IS_UPDATING_AND_INITIALIZING(new_rp)) {
        end_srv_update(rpupd, result, RS_REPLY);
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
    int is_curr;
    int process_allowed;
    int is_before_curr;

    is_curr = (rupdate.curr_rpupd == rpupd);
    is_after_curr = is_after_curr && !is_curr;

    if (UPD_IS_PREPARING_ONLY(rpupd)) {
      continue;
    }

    process_allowed = (!skip_rpupd || rpupd != skip_rpupd) &&
                      (!only_rpupd || rpupd == only_rpupd);
    if (!process_allowed) {
      continue;
    }

    is_before_curr = !is_curr && !is_after_curr;

    if (is_curr) {
      end_update_curr(rpupd, result, reply_flag);
    }
    else if (RUPDATE_IS_INITIALIZING()) {
      if (is_after_curr) {
        end_update_prepare_done(rpupd, result);
      }
      else if (is_before_curr) {
        end_update_initializing(rpupd, result);
      }
      else {
        assert(0);
      }
    }
    else {
      if (is_after_curr) {
        end_update_before_prepare(rpupd, result);
      }
      else if (is_before_curr) {
        end_update_prepare_done(rpupd, result);
      }
      else {
        assert(0);
      }
    }
  );
}

/*===========================================================================*
 *			    end_update_debug				     *
 *===========================================================================*/
void end_update_debug(char *file, int line, int result, int reply_flag)
{
    struct rprocupd *prev_rpupd, *rpupd;
    struct rproc *rp, *new_rp;
    int slot_nr;
    const int is_ok = (result == OK);
    const int is_initializing = RUPDATE_IS_INITIALIZING();

    assert(RUPDATE_IS_UPDATING());

    if (rs_verbose) {
        printf("RS: %s ending the update: result=%d, reply=%d at %s:%d\n",
               srv_to_string(rupdate.curr_rpupd->rp), result,
               (reply_flag == RS_REPLY), file, line);
    }

    if (result != OK && RUPDATE_IS_RS_INIT_DONE()) {
        if (rs_verbose) {
            printf("RS: update failed, new RS instance will now exit\n");
        }
        exit(1);
    }

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            if (!is_initializing) {
                request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
            }
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
        if (is_ok && !UPD_IS_PREPARING_ONLY(rpupd)) {
            new_rp = rpupd->rp;
            end_srv_init(new_rp);
        }
    );

    late_reply(rupdate.last_rpupd->rp, result);
    rupdate_upd_clear(rupdate.last_rpupd);
    RUPDATE_CLEAR();

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
        rp->r_pub->sys_flags &= ~(SF_VM_UPDATE | SF_VM_ROLLBACK | SF_VM_NOMMAP);
    }
}

/*===========================================================================*
*			      end_srv_update				     *
 *===========================================================================*/
void end_srv_update(struct rprocupd *rpupd, int result, int reply_flag)
{
  struct rproc *old_rp, *new_rp, *exiting_rp, *surviving_rp;
  struct rproc **rps = NULL;
  int nr_rps = 0, i;
  int is_success, is_reply;

  if (!rpupd || !rpupd->rp) return;

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  if (!new_rp || !new_rp->r_pub || !old_rp->r_pub) return;

  is_success = (result == OK);
  if (is_success && new_rp->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) {
    reply_flag = RS_CANCEL;
  }

  is_reply = (reply_flag == RS_REPLY);

  if (rs_verbose)
    printf("RS: ending update from %s to %s with result=%d, reply=%d\n",
      srv_to_string(old_rp), srv_to_string(new_rp), result, is_reply);

  surviving_rp = is_success ? new_rp : old_rp;
  exiting_rp = is_success ? old_rp : new_rp;

  surviving_rp->r_flags &= ~RS_INITIALIZING;
  surviving_rp->r_check_tm = 0;
  surviving_rp->r_alive_tm = getticks();

  rpupd->rp = surviving_rp;

  old_rp->r_new_rp = NULL;
  new_rp->r_old_rp = NULL;

  surviving_rp->r_flags &= ~(RS_UPDATING | RS_PREPARE_DONE | RS_INIT_DONE | RS_INIT_PENDING);

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
  if (rps && nr_rps > 0) {
    for (i = 0; i < nr_rps; i++) {
      struct rproc *rp = rps[i];
      if (!rp) continue;

      if (rp == old_rp && (rpupd->lu_flags & SEF_LU_DETACHED)) {
        message m;
        m.m_type = EDEADEPT;
        rp->r_flags |= RS_CLEANUP_DETACH;
        cleanup_service(rp);
        if (rp->r_pub) reply(rp->r_pub->endpoint, rp, &m);
      } else {
        cleanup_service(rp);
      }
    }
  }

  if (rs_verbose)
    printf("RS: %s ended the %s\n", srv_to_string(surviving_rp),
      srv_upd_to_string(rpupd));
}

