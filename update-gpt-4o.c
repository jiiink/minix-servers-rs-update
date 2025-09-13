
#include "inc.h"

/*===========================================================================*
 *			      rupdate_clear_upds			     *
 *===========================================================================*/
void rupdate_clear_upds()
{
  struct rprocupd *rpupd;
  while ((rpupd = rupdate.first_rpupd) != NULL) {
    rupdate.first_rpupd = rpupd->next;
    rupdate_upd_clear(rpupd);
  }
  rupdate.last_rpupd = NULL;
  RUPDATE_CLEAR();
}

/*===========================================================================*
 *			       rupdate_add_upd  			     *
 *===========================================================================*/
void rupdate_add_upd(struct rprocupd* rpupd) {
    struct rprocupd *prev_rpupd = NULL, *walk_rpupd = NULL;
    endpoint_t ep = rpupd->rp->r_pub->endpoint;
    int lu_flags;

    assert(rpupd->next_rpupd == NULL && rpupd->prev_rpupd == NULL);

    prev_rpupd = rupdate.last_rpupd;
    while (prev_rpupd != NULL && ((ep != RS_PROC_NR && prev_rpupd->rp->r_pub->endpoint == RS_PROC_NR) || 
          (ep != VM_PROC_NR && prev_rpupd->rp->r_pub->endpoint == VM_PROC_NR))) {
        prev_rpupd = prev_rpupd->prev_rpupd;
    }

    if (prev_rpupd == NULL) {
        rpupd->next_rpupd = rupdate.first_rpupd;
        rupdate.first_rpupd = rupdate.curr_rpupd = rpupd;
    } else {
        rpupd->next_rpupd = prev_rpupd->next_rpupd;
        rpupd->prev_rpupd = prev_rpupd;
        prev_rpupd->next_rpupd = rpupd;
    }

    if (rpupd->next_rpupd != NULL) {
        rpupd->next_rpupd->prev_rpupd = rpupd;
    } else {
        rupdate.last_rpupd = rpupd;
    }

    rupdate.num_rpupds++;

    lu_flags = rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS | SEF_LU_MULTI);
    if (lu_flags) {
        for (walk_rpupd = rupdate.first_rpupd; walk_rpupd != NULL; walk_rpupd = walk_rpupd->next_rpupd) {
            walk_rpupd->lu_flags |= lu_flags;
            walk_rpupd->init_flags |= lu_flags;
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
void rupdate_set_new_upd_flags(struct rprocupd* rpupd) {
    const int relevant_flags = SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS;

    if (rupdate.num_rpupds > 0) {
        rpupd->lu_flags |= SEF_LU_MULTI;
        rpupd->init_flags |= SEF_LU_MULTI;
    }

    if (rupdate.last_rpupd) {
        int lu_flags = rupdate.last_rpupd->lu_flags & relevant_flags;
        rpupd->lu_flags |= lu_flags;
        rpupd->init_flags |= lu_flags;
    }

    if (!UPD_IS_PREPARING_ONLY(rpupd)) {
        switch (rpupd->rp->r_pub->endpoint) {
            case VM_PROC_NR:
                rpupd->lu_flags |= SEF_LU_INCLUDES_VM;
                rpupd->init_flags |= SEF_LU_INCLUDES_VM;
                break;
            case RS_PROC_NR:
                rpupd->lu_flags |= SEF_LU_INCLUDES_RS;
                rpupd->init_flags |= SEF_LU_INCLUDES_RS;
                break;
            default:
                break;
        }
    }
}

/*===========================================================================*
 *			      rupdate_upd_init  			     *
 *===========================================================================*/
#include <stddef.h>
#include <string.h>

void rupdate_upd_init(struct rprocupd* rpupd, struct rproc *rp) {
  if (rpupd == NULL || rp == NULL) {
    return;
  }
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
    if (!rpupd) return;
    if (rpupd->rp && rpupd->rp->r_new_rp) {
        cleanup_service(rpupd->rp->r_new_rp);
    }
    if (rpupd->prepare_state_data_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data_gid);
    }
    struct prepare_state_data *psd = &rpupd->prepare_state_data;
    if (psd->size > 0) {
        if (psd->ipcf_els_gid != GRANT_INVALID) {
            cpf_revoke(psd->ipcf_els_gid);
        }
        if (psd->eval_gid != GRANT_INVALID) {
            cpf_revoke(psd->eval_gid);
        }
        free(psd->ipcf_els);
        free(psd->eval_addr);
    }
    rupdate_upd_init(rpupd, NULL);
}

/*===========================================================================*
 *			       rupdate_upd_move 			     *
 *===========================================================================*/
void rupdate_upd_move(struct rproc* src_rp, struct rproc* dst_rp) {
    dst_rp->r_upd = src_rp->r_upd;
    dst_rp->r_upd.rp = dst_rp;

    if (src_rp->r_new_rp) {
        dst_rp->r_new_rp = src_rp->r_new_rp;
        dst_rp->r_new_rp->r_old_rp = dst_rp;
        src_rp->r_new_rp = NULL;
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
}

/*===========================================================================*
 *		     request_prepare_update_service_debug		     *
 *===========================================================================*/
void request_prepare_update_service_debug(char *file, int line, struct rproc *rp, int state)
{
    message m;
    struct rprocpub *rpub = rp->r_pub;

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
    int no_reply = !(rp->r_flags & RS_PREPARE_DONE);
    rs_asynsend(rp, &m, no_reply);
}

/*===========================================================================*
 *				 srv_update				     *
 *===========================================================================*/
int srv_update(endpoint_t src_e, endpoint_t dst_e, int sys_upd_flags) {
    int r = OK;
    int is_vm_proc = (src_e == VM_PROC_NR);
    int is_vm_init_done = RUPDATE_IS_VM_INIT_DONE();
    int is_upd_vm_multi = RUPDATE_IS_UPD_VM_MULTI();
    int should_execute_vm_update = !is_upd_vm_multi || is_vm_init_done;

    if (is_vm_proc) {
        if (rs_verbose) {
            printf("RS: executing sys_update(%d, %d)\n", src_e, dst_e);
        }
        r = sys_update(src_e, dst_e, (sys_upd_flags & SF_VM_ROLLBACK) ? SYS_UPD_ROLLBACK : 0);
    } else if (should_execute_vm_update) {
        if (rs_verbose) {
            printf("RS: executing vm_update(%d, %d)\n", src_e, dst_e);
        }
        r = vm_update(src_e, dst_e, sys_upd_flags);
    } else if (rs_verbose) {
        printf("RS: skipping srv_update(%d, %d)\n", src_e, dst_e);
    }

    return r;
}

/*===========================================================================*
 *				update_service				     *
 *===========================================================================*/
int update_service(struct rproc **src_rpp, struct rproc **dst_rpp, int swap_flag, int sys_upd_flags) {
    struct rproc *src_rp = *src_rpp;
    struct rproc *dst_rp = *dst_rpp;
    struct rprocpub *src_rpub = src_rp->r_pub;
    struct rprocpub *dst_rpub = dst_rp->r_pub;
    int pid;
    endpoint_t endpoint;
    int r;

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
void rollback_service(struct rproc **new_rpp, struct rproc **old_rpp) {
    struct rproc *rp;
    int r = OK;

    if ((*old_rpp)->r_pub->endpoint == RS_PROC_NR) {
        endpoint_t me = NONE;
        char name[20];
        int priv_flags, init_flags;

        r = sys_whoami(&me, name, sizeof(name), &priv_flags, &init_flags);
        if (r != OK || me == RS_PROC_NR) return;

        r = vm_update((*new_rpp)->r_pub->endpoint, (*old_rpp)->r_pub->endpoint, SF_VM_ROLLBACK);
        if (rs_verbose) printf("RS: %s performed rollback\n", srv_to_string(*new_rpp));

        for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
            if (rp->r_flags & RS_ACTIVE) rp->r_check_tm = 0;
        }
    } else {
        int swap_flag = ((*new_rpp)->r_flags & RS_INIT_PENDING) ? RS_DONTSWAP : RS_SWAP;
        if (rs_verbose) printf("RS: %s performs rollback\n", srv_to_string(*new_rpp));

        if (swap_flag == RS_SWAP) {
            sys_privctl((*new_rpp)->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
        }
        r = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
    }

    if (r != OK) {
        fprintf(stderr, "Error: Rollback failed\n");
        exit(EXIT_FAILURE);
    }
}

/*===========================================================================*
 *				update_period				     *
 *===========================================================================*/
void update_period(message *m_ptr) {
    clock_t now = m_ptr->m_notify.timestamp;
    struct rprocupd *rpupd = rupdate.curr_rpupd;
    struct rproc *rp = rpupd->rp;
    struct rprocpub *rpub = rp->r_pub;

    if (rpupd->prepare_maxtime > 0 && 
        (now - rpupd->prepare_tm > rpupd->prepare_maxtime)) {
        printf("RS: update failed: maximum prepare time reached\n");
        end_update(EINTR, RS_CANCEL);
    }
}

/*===========================================================================*
 *			    start_update_prepare			     *
 *===========================================================================*/
#include <errno.h>
#include <stdio.h>
#include <assert.h>

#define RS_PROC_NR 1
#define VM_PROC_NR 2
#define SF_VM_UPDATE 0x01
#define SF_VM_NOMMAP 0x02
#define OK 0
#define EINVAL 22
#define EAGAIN 11
#define ESRCH 3
#define RS_REPLY 100

struct rprocupd {
    struct rproc *rp;
    int state_endpoint;
    int lu_flags;
};

struct rproc {
    struct rproc *r_new_rp;
    struct r_pub *r_pub;
};

struct r_pub {
    int endpoint;
    int old_endpoint;
    int new_endpoint;
    int sys_flags;
};

int RUPDATE_IS_UPD_SCHEDULED() { return 1; }
int rs_is_idle() { return 1; }
int rs_verbose = 1;
int UPD_IS_PREPARING_ONLY(struct rprocupd *rpupd) { return 0; }
int RUPDATE_IS_UPD_VM_MULTI() { return 1; }
void RUPDATE_ITER(struct rprocupd *first, struct rprocupd *prev, struct rprocupd *current, void (*func)) {}
void* start_update_prepare_next() { return (void *)1; }
void end_update(int status, int reply_type) {}
void abort_update_proc(int error) {}

int start_update_prepare(int allow_retries) {
    struct rprocupd *prev_rpupd = NULL, *rpupd = NULL;

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

    if (RUPDATE_IS_UPD_VM_MULTI()) {
        RUPDATE_ITER(NULL, prev_rpupd, rpupd, {
            struct rproc *rp = rpupd->rp;
            struct rproc *new_rp = rp->r_new_rp;

            if (!UPD_IS_PREPARING_ONLY(rpupd) && rp && new_rp) {
                rp->r_pub->old_endpoint = rpupd->state_endpoint;
                rp->r_pub->new_endpoint = rp->r_pub->endpoint;
                rp->r_pub->sys_flags |= SF_VM_UPDATE;
                if (rpupd->lu_flags & SF_VM_NOMMAP) {
                    rp->r_pub->sys_flags |= SF_VM_NOMMAP;
                }
            }
        });
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
struct rprocupd* start_update_prepare_next() {
    struct rprocupd *rpupd, *prev_rpupd, *walk_rpupd;
    struct rproc *rp, *new_rp;

    rpupd = RUPDATE_IS_UPDATING() ? rupdate.curr_rpupd->next_rpupd : rupdate.first_rpupd;

    if (!rpupd) {
        return NULL;
    }

    if (RUPDATE_IS_UPD_VM_MULTI() && rpupd == rupdate.vm_rpupd) {
        RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, walk_rpupd,
            if (!UPD_IS_PREPARING_ONLY(walk_rpupd) && walk_rpupd != rupdate.vm_rpupd) {
                rp = walk_rpupd->rp;
                new_rp = rp->r_new_rp;
                assert(rp && new_rp);
                if (rs_verbose) {
                    printf("RS: preparing VM for %s -> %s\n", srv_to_string(rp), srv_to_string(new_rp));
                }
                vm_prepare(rp->r_pub->new_endpoint, new_rp->r_pub->endpoint, rp->r_pub->sys_flags);
            }
        );
    }

    rupdate.flags |= RS_UPDATING;

    while (rpupd) {
        rupdate.curr_rpupd = rpupd;
        request_prepare_update_service(rupdate.curr_rpupd->rp, rupdate.curr_rpupd->prepare_state);
        if (!UPD_IS_PREPARING_ONLY(rpupd) || !rupdate.curr_rpupd->next_rpupd) {
            break;
        }
        rpupd = rupdate.curr_rpupd->next_rpupd;
    }

    return rpupd;
}

/*===========================================================================*
 *				start_update				     *
 *===========================================================================*/
#include <assert.h>
#include <stdio.h>

#define OK 0
#define EINTR -1
#define RS_INIT 1
#define RS_INITIALIZING 2
#define VM_PROC_NR 3

struct message {
  int m_type;
  int m_source;
  struct {
    int result;
  } m_rs_init;
};

struct rprocupd {
  struct rprocupd *next;
  int rp;
};

struct {
  struct rprocupd *first_rpupd;
  struct rprocupd *last_rpupd;
  struct rprocupd *curr_rpupd;
  struct rprocupd *vm_rpupd;
  int num_rpupds;
  int num_init_ready_pending;
  int flags;
} rupdate;

int rs_verbose;
int r = OK;

#define RUPDATE_IS_UPD_MULTI() (1)  // Stub for condition check
#define RUPDATE_IS_UPDATING() (1)   // Stub for condition check
#define RUPDATE_IS_UPD_VM_MULTI() (1)  // Stub for condition check
#define UPD_IS_PREPARING_ONLY(r) (0) // Stub for condition check
#define UPD_INIT_MAXTIME(r) (1000)  // Stub for obtaining max time

#define RUPDATE_ITER(start, prev, curr, block) \
  for (prev = NULL, curr = start; curr != NULL; prev = curr, curr = curr->next) block

void request_prepare_update_service(int rp, int state) {}
int start_srv_update(struct rprocupd *rpupd) { return OK; }
int complete_srv_update(struct rprocupd *rpupd) { return OK; }
int rs_receive_ticks(int proc_nr, struct message *m_ptr, int *status_ptr, int timeout) { return OK; }
void end_update(int status, int flags) {}
void do_init_ready(struct message *m_ptr) {}
void reply(int proc_nr, void *addr, struct message *m_ptr) {}

int start_update() {
  if (rs_verbose) {
    printf("RS: starting a %s-component update process\n", RUPDATE_IS_UPD_MULTI() ? "multi" : "single");
  }

  assert(RUPDATE_IS_UPDATING());
  assert(rupdate.num_rpupds > 0);
  assert(rupdate.num_init_ready_pending == 0);
  assert(rupdate.first_rpupd);
  assert(rupdate.last_rpupd);
  assert(rupdate.curr_rpupd == rupdate.last_rpupd);

  rupdate.flags |= RS_INITIALIZING;
  int init_ready_pending = 0;

  struct rprocupd *prev_rpupd = NULL, *rpupd = NULL;

  // Cancel update for prepare-only services
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd, {
    if (UPD_IS_PREPARING_ONLY(rpupd)) {
      request_prepare_update_service(rpupd->rp, 0);  // SEF_LU_STATE_NULL is 0
    }
  });

  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd, {
    rupdate.curr_rpupd = rpupd;
    if (!UPD_IS_PREPARING_ONLY(rpupd)) {
      init_ready_pending = 1;
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
    }
  });

  if (!init_ready_pending) {
    end_update(OK, 0);
    return OK;
  }

  if (RUPDATE_IS_UPD_VM_MULTI()) {
    struct message m;
    if (rs_verbose) {
      printf("RS: waiting for VM to initialize...\n");
    }
    r = rs_receive_ticks(VM_PROC_NR, &m, NULL, UPD_INIT_MAXTIME(rupdate.vm_rpupd));
    if (r != OK || m.m_type != RS_INIT || m.m_rs_init.result != OK) {
      r = (r == OK && m.m_type == RS_INIT) ? m.m_rs_init.result : EINTR;
      m.m_source = VM_PROC_NR;
      m.m_type = RS_INIT;
      m.m_rs_init.result = r;
    }
    do_init_ready(&m);

    if (r == OK) {
      m.m_type = OK;
      reply(VM_PROC_NR, NULL, &m);
      RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd, {
        if (!UPD_IS_PREPARING_ONLY(rpupd) && rpupd != rupdate.vm_rpupd) {
          r = complete_srv_update(rpupd);
          if (r != OK) {
            return r;
          }
        }
      });
    }
  }

  return OK;
}

/*===========================================================================*
 *			      start_srv_update				     *
 *===========================================================================*/
int start_srv_update(struct rprocupd *rpupd) {
    struct rproc *old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp->r_new_rp;
    int sys_upd_flags = 0;

    if (old_rp == NULL || new_rp == NULL) {
        fprintf(stderr, "RS: Invalid service update descriptors.\n");
        return EINVAL;
    }

    if (rs_verbose) {
        printf("RS: %s starting the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
    }

    rupdate.num_init_ready_pending++;
    new_rp->r_flags |= (RS_INITIALIZING | RS_INIT_PENDING);

    if ((rpupd->lu_flags & SEF_LU_NOMMAP) != 0) {
        sys_upd_flags |= SF_VM_NOMMAP;
    }

    if (old_rp->r_pub->endpoint != RS_PROC_NR) {
        int update_result = update_service(&old_rp, &new_rp, RS_SWAP, sys_upd_flags);
        if (update_result != OK) {
            end_update(update_result, RS_REPLY);
            fprintf(stderr, "RS: update failed: error %d\n", update_result);
            return update_result;
        }
    }

    return OK;
}

/*===========================================================================*
 *			   complete_srv_update				     *
 *===========================================================================*/
int complete_srv_update(struct rprocupd *rpupd)
{
    struct rproc *old_rp = rpupd->rp, *new_rp = old_rp->r_new_rp;
    int r = OK;

    assert(old_rp && new_rp);

    if (rs_verbose) {
        printf("RS: %s completing the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
    }

    new_rp->r_flags &= ~RS_INIT_PENDING;

    if (old_rp->r_pub->endpoint == RS_PROC_NR) {
        r = init_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
        if (r != OK) {
            panic("unable to initialize the new RS instance: %d", r);
            return ERESTART;
        }

        if (rs_verbose) {
            printf("RS: %s is the new RS instance we'll yield control to\n", srv_to_string(new_rp));
        }
        
        r = sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_YIELD, NULL);
        if (r != OK) {
            panic("unable to yield control to the new RS instance: %d", r);
            rollback_service(&new_rp, &old_rp);
            end_update(ERESTART, RS_REPLY);
            printf("RS: update failed: state transfer failed for the new RS instance\n");
            return ERESTART;
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
int abort_update_proc(int reason) {
  if (reason == OK) {
    return EINVAL;
  }

  if (!RUPDATE_IS_UPDATING() && !RUPDATE_IS_UPD_SCHEDULED()) {
    return EINVAL;
  }

  if (rs_verbose) {
    printf("RS: aborting the %s update process prematurely\n",
           RUPDATE_IS_UPDATING() ? "in-progress" : "scheduled");
  }

  if (!RUPDATE_IS_UPDATING()) {
    rupdate_clear_upds();
    return OK;
  }

  int update_flags = rupdate.flags;
  int reply_type = (update_flags & RS_INITIALIZING) ? RS_REPLY : RS_CANCEL;
  end_update(reason, reply_type);

  return OK;
}

/*===========================================================================*
 *			    end_update_curr				     *
 *===========================================================================*/
static void end_update_curr(struct rprocupd *rpupd, int result, int reply_flag) {
    struct rproc *old_rp, *new_rp;
    
    assert(rpupd == rupdate.curr_rpupd);
    
    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;
    
    assert(old_rp != NULL);
    assert(new_rp != NULL);

    if (result != OK && SRV_IS_UPDATING_AND_INITIALIZING(new_rp) && rpupd != rupdate.rs_rpupd) {
        rollback_service(&new_rp, &old_rp);
    }
    end_srv_update(rpupd, result, reply_flag);
}

/*===========================================================================*
 *			end_update_before_prepare			     *
 *===========================================================================*/
#include <assert.h>

static void end_update_before_prepare(struct rprocupd *rpupd, int result) {
    if (result == OK) {
        return;
    }

    struct rproc *old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp ? old_rp->r_new_rp : NULL;

    if (old_rp && new_rp) {
        cleanup_service(new_rp);
    }
}

/*===========================================================================*
 *			 end_update_prepare_done			     *
 *===========================================================================*/
#include <assert.h>

static void end_update_prepare_done(struct rprocupd *rpupd, int result) {
    if (RUPDATE_IS_INITIALIZING() || result == OK || (rpupd->rp->r_flags & RS_INITIALIZING)) {
        return;
    }

    end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			 end_update_initializing			     *
 *===========================================================================*/
static void end_update_initializing(struct rprocupd *rpupd, int result) {
    if (!rpupd || !rpupd->rp || !rpupd->rp->r_new_rp) {
        return; // Handle unexpected null pointers
    }

    struct rproc *old_rp = rpupd->rp;
    struct rproc *new_rp = old_rp->r_new_rp;

    if (!SRV_IS_UPDATING_AND_INITIALIZING(new_rp)) {
        return; // Early return if not updating and initializing
    }

    if (result != OK && rpupd != rupdate.rs_rpupd) {
        rollback_service(&new_rp, &old_rp);  // Rollback in case of failures
    }

    end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			    end_update_rev_iter				     *
 *===========================================================================*/
static void end_update_rev_iter(int result, int reply_flag, struct rprocupd *skip_rpupd, struct rprocupd *only_rpupd) {
    struct rprocupd *prev_rpupd, *rpupd;
    int isProcessingCurrent = 0;

    RUPDATE_REV_ITER(rupdate.last_rpupd, prev_rpupd, rpupd,
        int isCurrent = (rupdate.curr_rpupd == rpupd);
        isProcessingCurrent |= isCurrent;

        if (!UPD_IS_PREPARING_ONLY(rpupd) && 
            (!skip_rpupd || rpupd != skip_rpupd) && 
            (!only_rpupd || rpupd == only_rpupd)) {

            if (isCurrent) {
                end_update_curr(rpupd, result, reply_flag);
            } else if (RUPDATE_IS_INITIALIZING()) {
                if (!isProcessingCurrent) {
                    end_update_initializing(rpupd, result);
                } else {
                    end_update_prepare_done(rpupd, result);
                }
            } else {
                if (!isProcessingCurrent) {
                    end_update_before_prepare(rpupd, result);
                }
            }
        }
    );
}

/*===========================================================================*
 *			    end_update_debug				     *
 *===========================================================================*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void end_update_debug(char *file, int line, int result, int reply_flag) {
    struct rprocupd *rpupd;
    int slot_nr;

    assert(RUPDATE_IS_UPDATING());

    if (rs_verbose) {
        printf("RS: %s ending the update: result=%d, reply=%d at %s:%d\n",
               srv_to_string(rupdate.curr_rpupd->rp), result, (reply_flag == RS_REPLY),
               file, line);
    }

    if (result != OK && RUPDATE_IS_RS_INIT_DONE()) {
        if (rs_verbose) {
            printf("RS: update failed, new RS instance will now exit\n");
        }
        exit(1);
    }

    RUPDATE_ITER(rupdate.first_rpupd, NULL, rpupd, {
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            if (!RUPDATE_IS_INITIALIZING()) {
                request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
            }
            rpupd->rp->r_flags &= ~RS_PREPARE_DONE;
        }
    });

    end_update_rev_iter(result, reply_flag, rupdate.vm_rpupd, NULL);
    if (rupdate.vm_rpupd) {
        end_update_rev_iter(result, reply_flag, NULL, rupdate.vm_rpupd);
    }

    RUPDATE_ITER(rupdate.first_rpupd, NULL, rpupd, {
        rupdate_upd_clear(rpupd);
        if (result == OK && !UPD_IS_PREPARING_ONLY(rpupd)) {
            end_srv_init(rpupd->rp);
        }
    });

    late_reply(rupdate.last_rpupd->rp, result);
    rupdate_upd_clear(rupdate.last_rpupd);
    RUPDATE_CLEAR();

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
        rp->r_pub->sys_flags &= ~(SF_VM_UPDATE | SF_VM_ROLLBACK | SF_VM_NOMMAP);
    }
}

/*===========================================================================*
*			      end_srv_update				     *
 *===========================================================================*/
void end_srv_update(struct rprocupd *rpupd, int result, int reply_flag) {
    struct rproc *old_rp, *new_rp, *exiting_rp, *surviving_rp;
    struct rproc **rps;
    int nr_rps = 0, i = 0;

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);

    if (result == OK && new_rp->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) {
        reply_flag = RS_CANCEL;
    }

    if (rs_verbose) {
        printf("RS: ending update from %s to %s with result=%d, reply=%d\n",
               srv_to_string(old_rp), srv_to_string(new_rp), result, (reply_flag == RS_REPLY));
    }

    surviving_rp = (result == OK ? new_rp : old_rp);
    exiting_rp = (result == OK ? old_rp : new_rp);
    surviving_rp->r_flags &= ~RS_INITIALIZING;
    surviving_rp->r_check_tm = 0;
    surviving_rp->r_alive_tm = getticks();

    rpupd->rp = surviving_rp;

    old_rp->r_new_rp = NULL;
    new_rp->r_old_rp = NULL;

    surviving_rp->r_flags &= ~(RS_UPDATING | RS_PREPARE_DONE | RS_INIT_DONE | RS_INIT_PENDING);
    
    if (reply_flag == RS_REPLY) {
        message m;
        m.m_type = result;
        reply(surviving_rp->r_pub->endpoint, surviving_rp, &m);
    } else if (reply_flag == RS_CANCEL && !(surviving_rp->r_flags & RS_TERMINATED)) {
        request_prepare_update_service(surviving_rp, SEF_LU_STATE_NULL);
    }

    get_service_instances(exiting_rp, &rps, &nr_rps);
    for (i = 0; i < nr_rps; i++) {
        if (rps[i] == old_rp && (rpupd->lu_flags & SEF_LU_DETACHED)) {
            message m;
            m.m_type = EDEADEPT;
            rps[i]->r_flags |= RS_CLEANUP_DETACH;
            cleanup_service(rps[i]);
            reply(rps[i]->r_pub->endpoint, rps[i], &m);
        } else {
            cleanup_service(rps[i]);
        }
    }

    if (rs_verbose) {
        printf("RS: %s ended the %s\n", srv_to_string(surviving_rp), srv_upd_to_string(rpupd));
    }
}

