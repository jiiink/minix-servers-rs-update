
#include "inc.h"

/*===========================================================================*
 *			      rupdate_clear_upds			     *
 *===========================================================================*/
void rupdate_clear_upds()
{
  struct rprocupd *current_rpupd = rupdate.first_rpupd;
  struct rprocupd *next_rpupd;

  while (current_rpupd != NULL) {
    next_rpupd = current_rpupd->next;
    rupdate_upd_clear(current_rpupd);
    current_rpupd = next_rpupd;
  }

  RUPDATE_CLEAR();
}

/*===========================================================================*
 *			       rupdate_add_upd  			     *
 *===========================================================================*/
void rupdate_add_upd(struct rprocupd* rpupd)
{
  endpoint_t ep;
  struct rprocupd *insert_before_node = NULL;
  int lu_flags_to_propagate;

  /* Basic sanity checks for the input descriptor. */
  assert(rpupd != NULL);
  assert(rpupd->next_rpupd == NULL);
  assert(rpupd->prev_rpupd == NULL);

  ep = rpupd->rp->r_pub->endpoint;

  /* Determine the node *before* which 'rpupd' should be inserted.
   * This maintains the desired order: OTHERS, then VM, then RS.
   * If the list is empty or no suitable predecessor is found,
   * 'insert_before_node' will remain NULL or point to the first element.
   */
  insert_before_node = rupdate.first_rpupd; // Start searching from the beginning

  if (ep == VM_PROC_NR) {
      // VM update descriptors should be inserted before any RS update descriptors.
      while (insert_before_node != NULL &&
             insert_before_node->rp->r_pub->endpoint != RS_PROC_NR) {
          insert_before_node = insert_before_node->next_rpupd;
      }
  } else if (ep != RS_PROC_NR) { // All other non-RS endpoints (OTHERS)
      // Other update descriptors should be inserted before any VM or RS update descriptors.
      while (insert_before_node != NULL &&
             insert_before_node->rp->r_pub->endpoint != VM_PROC_NR &&
             insert_before_node->rp->r_pub->endpoint != RS_PROC_NR) {
          insert_before_node = insert_before_node->next_rpupd;
      }
  }
  // If ep == RS_PROC_NR, 'insert_before_node' will iterate until NULL (or stay NULL if list is empty),
  // effectively placing RS at the very end, as intended.

  /* Perform the general doubly linked list insertion: insert 'rpupd' before 'insert_before_node'. */
  rpupd->next_rpupd = insert_before_node;

  if (insert_before_node != NULL) {
      // If inserting in the middle or at the head (but not empty list)
      rpupd->prev_rpupd = insert_before_node->prev_rpupd;
      insert_before_node->prev_rpupd = rpupd;
  } else {
      // If 'insert_before_node' is NULL, we are inserting at the end of the list.
      rpupd->prev_rpupd = rupdate.last_rpupd;
  }

  if (rpupd->prev_rpupd != NULL) {
      // If not inserting at the head of the list
      rpupd->prev_rpupd->next_rpupd = rpupd;
  } else {
      // If 'rpupd->prev_rpupd' is NULL, we are inserting at the head of the list.
      rupdate.first_rpupd = rpupd;
      rupdate.curr_rpupd = rpupd; /* Preserve original behavior for 'curr_rpupd'. */
  }

  if (rpupd->next_rpupd == NULL) {
      // If 'rpupd->next_rpupd' is NULL, 'rpupd' is now the last node in the list.
      rupdate.last_rpupd = rpupd;
  }

  rupdate.num_rpupds++;

  /* Propagate relevant flags from the new descriptor to all existing descriptors. */
  lu_flags_to_propagate = rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS | SEF_LU_MULTI);
  if (lu_flags_to_propagate) {
      struct rprocupd *current_node = rupdate.first_rpupd;
      while (current_node != NULL) {
          current_node->lu_flags |= lu_flags_to_propagate;
          current_node->init_flags |= lu_flags_to_propagate;
          current_node = current_node->next_rpupd;
      }
  }

  /* Set VM/RS update descriptor pointers if they are not already set.
   * This ensures that rupdate.vm_rpupd/rs_rpupd point to the *first* encountered
   * descriptor (in logical insertion order) that has the respective flag and
   * wasn't already assigned.
   */
  if (!rupdate.vm_rpupd && (lu_flags_to_propagate & SEF_LU_INCLUDES_VM)) {
      rupdate.vm_rpupd = rpupd;
  } else if (!rupdate.rs_rpupd && (lu_flags_to_propagate & SEF_LU_INCLUDES_RS)) {
      rupdate.rs_rpupd = rpupd;
  }
}

/*===========================================================================*
 *			  rupdate_set_new_upd_flags  			     *
 *===========================================================================*/
static void set_rprocupd_flags(struct rprocupd* rpupd_ptr, unsigned int flags_to_set)
{
    rpupd_ptr->lu_flags |= flags_to_set;
    rpupd_ptr->init_flags |= flags_to_set;
}

void rupdate_set_new_upd_flags(struct rprocupd* rpupd)
{
  if (!rpupd) {
      return;
  }

  if (rupdate.num_rpupds > 0) {
      set_rprocupd_flags(rpupd, SEF_LU_MULTI);
  }

  if (rupdate.last_rpupd) {
      unsigned int propagated_flags = rupdate.last_rpupd->lu_flags & (SEF_LU_INCLUDES_VM | SEF_LU_INCLUDES_RS);
      if (propagated_flags) {
          set_rprocupd_flags(rpupd, propagated_flags);
      }
  }

  if (UPD_IS_PREPARING_ONLY(rpupd)) {
      return;
  }

  if (rpupd->rp && rpupd->rp->r_pub) {
      if (rpupd->rp->r_pub->endpoint == VM_PROC_NR) {
          set_rprocupd_flags(rpupd, SEF_LU_INCLUDES_VM);
      }
      else if (rpupd->rp->r_pub->endpoint == RS_PROC_NR) {
          set_rprocupd_flags(rpupd, SEF_LU_INCLUDES_RS);
      }
  }
}

/*===========================================================================*
 *			      rupdate_upd_init  			     *
 *===========================================================================*/
void rupdate_upd_init(struct rprocupd* rpupd, struct rproc *rp)
{
  if (rpupd == NULL) {
    return;
  }
  memset(rpupd, 0, sizeof(*(rpupd)));
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
  if(rpupd->rp->r_new_rp) {
      cleanup_service(rpupd->rp->r_new_rp);
      rpupd->rp->r_new_rp = NULL;
  }

  if(rpupd->prepare_state_data_gid != GRANT_INVALID) {
      cpf_revoke(rpupd->prepare_state_data_gid);
      rpupd->prepare_state_data_gid = GRANT_INVALID;
  }

  if(rpupd->prepare_state_data.size > 0) {
      if(rpupd->prepare_state_data.ipcf_els_gid != GRANT_INVALID) {
          cpf_revoke(rpupd->prepare_state_data.ipcf_els_gid);
          rpupd->prepare_state_data.ipcf_els_gid = GRANT_INVALID;
      }
      if(rpupd->prepare_state_data.eval_gid != GRANT_INVALID) {
          cpf_revoke(rpupd->prepare_state_data.eval_gid);
          rpupd->prepare_state_data.eval_gid = GRANT_INVALID;
      }

      free(rpupd->prepare_state_data.ipcf_els);
      rpupd->prepare_state_data.ipcf_els = NULL;

      free(rpupd->prepare_state_data.eval_addr);
      rpupd->prepare_state_data.eval_addr = NULL;

      rpupd->prepare_state_data.size = 0;
  }

  rupdate_upd_init(rpupd,NULL);
}

/*===========================================================================*
 *			       rupdate_upd_move 			     *
 *===========================================================================*/
#include <assert.h>

void rupdate_upd_move(struct rproc* src_rp, struct rproc* dst_rp)
{
  dst_rp->r_upd = src_rp->r_upd;
  dst_rp->r_upd.rp = dst_rp;

  if (src_rp->r_new_rp != NULL) {
    assert(dst_rp->r_new_rp == NULL);
    dst_rp->r_new_rp = src_rp->r_new_rp;
    dst_rp->r_new_rp->r_old_rp = dst_rp;
  }

  if (dst_rp->r_upd.prev_rpupd != NULL) {
    dst_rp->r_upd.prev_rpupd->next_rpupd = &dst_rp->r_upd;
  }
  if (dst_rp->r_upd.next_rpupd != NULL) {
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

  if(state != SEF_LU_STATE_NULL) {
      struct rprocupd *rpupd = &rp->r_upd;
      rpupd->prepare_tm = getticks();
      if(!UPD_IS_PREPARING_ONLY(rpupd)) {
          assert(rp->r_new_rp);
          rp->r_flags |= RS_UPDATING;
          rp->r_new_rp->r_flags |= RS_UPDATING;
      }
      else {
          assert(!rp->r_new_rp);
      }

      m.m_rs_update.flags = rpupd->lu_flags;
      m.m_rs_update.state_data_gid = rpupd->prepare_state_data_gid;

      if(rs_verbose)
          printf("RS: %s being requested to prepare for the %s at %s:%d\n", 
              srv_to_string(rp), srv_upd_to_string(rpupd), file, line);
  }
  else {
      if(rs_verbose)
          printf("RS: %s being requested to cancel the update at %s:%d\n", 
              srv_to_string(rp), file, line);
  }

  m.m_type = RS_LU_PREPARE;
  m.m_rs_update.state = state;
  no_reply = !(rp->r_flags & RS_PREPARE_DONE);
  rs_asynsend(rp, &m, no_reply);
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
    int kernel_update_flags = (sys_upd_flags & SF_VM_ROLLBACK) ? SYS_UPD_ROLLBACK : 0;
    r = sys_update(src_e, dst_e, kernel_update_flags);
  } else if (!RUPDATE_IS_UPD_VM_MULTI() || RUPDATE_IS_VM_INIT_DONE()) {
    if (rs_verbose) {
      printf("RS: executing vm_update(%d, %d)\n", src_e, dst_e);
    }
    r = vm_update(src_e, dst_e, sys_upd_flags);
  } else {
    if (rs_verbose) {
      printf("RS: skipping srv_update(%d, %d)\n", src_e, dst_e);
    }
    r = OK;
  }

  return r;
}

/*===========================================================================*
 *				update_service				     *
 *===========================================================================*/
int update_service(struct rproc **src_rpp, struct rproc **dst_rpp, int swap_flag, int sys_upd_flags)
{
  int r = OK; /* Initialize return code for safety */
  struct rproc *src_rp;
  struct rproc *dst_rp;
  struct rprocpub *src_rpub;
  struct rprocpub *dst_rpub;
  int pid;
  endpoint_t endpoint;

  src_rp = *src_rpp;
  dst_rp = *dst_rpp;
  src_rpub = src_rp->r_pub;
  dst_rpub = dst_rp->r_pub;

  if (rs_verbose) {
      printf("RS: %s updating into %s\n",
          srv_to_string(src_rp), srv_to_string(dst_rp));
  }

  /* Swap the slots of the two processes when asked to. */
  if (swap_flag == RS_SWAP) {
      if ((r = srv_update(src_rpub->endpoint, dst_rpub->endpoint, sys_upd_flags)) != OK) {
          return r;
      }
  }

  /* Swap slots here as well. */
  pid = src_rp->r_pid;
  endpoint = src_rpub->endpoint;

  swap_slot(&src_rp, &dst_rp);

  /* Reassign pids and endpoints. */
  src_rp->r_pid = dst_rp->r_pid;
  src_rp->r_pub->endpoint = dst_rp->r_pub->endpoint;
  rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)] = src_rp;
  dst_rp->r_pid = pid;
  dst_rp->r_pub->endpoint = endpoint;
  rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)] = dst_rp;

  /* Update in-RS priv structs */
  if ((r = sys_getpriv(&src_rp->r_priv, src_rp->r_pub->endpoint)) != OK) {
    panic("RS: update: could not update RS copies of priv of src: %d\n", r);
  }
  if ((r = sys_getpriv(&dst_rp->r_priv, dst_rp->r_pub->endpoint)) != OK) {
    panic("RS: update: could not update RS copies of priv of dst: %d\n", r);
  }

  /* Adjust input pointers. */
  *src_rpp = src_rp;
  *dst_rpp = dst_rp;

  /* Make the new version active. */
  activate_service(dst_rp, src_rp);

  if (rs_verbose) {
      printf("RS: %s updated into %s\n",
          srv_to_string(src_rp), srv_to_string(dst_rp));
  }

  return OK;
}

/*===========================================================================*
 *			      rollback_service				     *
 *===========================================================================*/
int rollback_service(struct rproc **new_rpp, struct rproc **old_rpp)
{
  struct rproc *rp;
  int result;

  if ((*old_rpp)->r_pub->endpoint == RS_PROC_NR) {
      endpoint_t me = NONE;
      char name[20];
      int priv_flags, init_flags;

      result = sys_whoami(&me, name, sizeof(name), &priv_flags, &init_flags);
      if (result != OK) {
          return result;
      }

      if (me != RS_PROC_NR) {
          result = vm_update((*new_rpp)->r_pub->endpoint, (*old_rpp)->r_pub->endpoint, SF_VM_ROLLBACK);
          if (result != OK) {
              return result;
          }
          if (rs_verbose) {
              printf("RS: %s performed rollback\n", srv_to_string(*new_rpp));
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
          printf("RS: %s performs rollback\n", srv_to_string(*new_rpp));
      }

      if (swap_flag == RS_SWAP) {
          result = sys_privctl((*new_rpp)->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
          if (result != OK) {
              return result;
          }
      }
      result = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
      if (result != OK) {
          return result;
      }
  }

  return OK;
}

/*===========================================================================*
 *				update_period				     *
 *===========================================================================*/
void update_period(message *m_ptr)
{
  clock_t now = m_ptr->m_notify.timestamp;
  struct rprocupd *rpupd = rupdate.curr_rpupd;

  if (rpupd == NULL) {
    fprintf(stderr, "RS: Warning: update_period called with no active update process. Ignoring.\n");
    return;
  }

  bool has_update_timed_out = (rpupd->prepare_maxtime > 0) &&
                              (now - rpupd->prepare_tm > rpupd->prepare_maxtime);

  if (has_update_timed_out) {
    printf("RS: update failed: maximum prepare time reached\n");
    end_update(EINTR, RS_CANCEL);
  }
}

/*===========================================================================*
 *			    start_update_prepare			     *
 *===========================================================================*/
#include <stdio.h>
#include <assert.h>

/* Assume necessary structures, macros, and global variables are defined elsewhere.
 * For example:
 * struct rprocupd {
 *     struct rproc *rp;
 *     int state_endpoint;
 *     unsigned int lu_flags;
 * };
 * struct rproc {
 *     struct rproc *r_new_rp;
 *     struct rproc_pub *r_pub;
 * };
 * struct rproc_pub {
 *     int endpoint;
 *     int old_endpoint;
 *     int new_endpoint;
 *     unsigned int sys_flags;
 * };
 *
 * struct rupdate_info {
 *     struct rprocupd *rs_rpupd;
 *     struct rprocupd *vm_rpupd;
 *     struct rprocupd *first_rpupd;
 *     struct rprocupd *last_rpupd;
 * };
 * extern struct rupdate_info rupdate;
 *
 * extern int rs_verbose;
 *
 * #define RUPDATE_IS_UPD_SCHEDULED() (1)
 * #define rs_is_idle() (1)
 * #define abort_update_proc(err) ((void)err)
 * #define RUPDATE_IS_UPD_VM_MULTI() (1)
 * #define UPD_IS_PREPARING_ONLY(rpupd) (0)
 * #define RUPDATE_ITER(first, prev, curr, body) \
 *     for (curr = (first); curr != NULL; prev = curr, curr = (curr)->next_rpupd) { body }
 * #define start_update_prepare_next() (NULL)
 * #define end_update(status, reply) ((void)status, (void)reply)
 *
 * #define OK 0
 * #define EINVAL 22
 * #define EAGAIN 11
 * #define ESRCH 3
 *
 * #define RS_PROC_NR 0
 * #define VM_PROC_NR 1
 *
 * #define SF_VM_UPDATE (1 << 0)
 * #define SF_VM_NOMMAP (1 << 1)
 * #define SEF_LU_NOMMAP (1 << 0)
 */

int start_update_prepare(int allow_retries)
{
  struct rprocupd *prev_rpupd;
  struct rprocupd *rpupd;
  struct rproc *rp;
  struct rproc *new_rp;

  if (!RUPDATE_IS_UPD_SCHEDULED()) {
      return EINVAL;
  }

  if (!rs_is_idle()) {
      /* Log that the system is not idle. This print is not conditional on rs_verbose. */
      printf("RS: not idle now, try again\n");
      if (!allow_retries) {
          abort_update_proc(EAGAIN);
      }
      return EAGAIN;
  }

  if (rs_verbose) {
      printf("RS: starting the preparation phase of the update process\n");
  }

  /* Assertions for internal consistency of update structures.
   * These assume design invariants; if these conditions can legitimately fail
   * at runtime due to external factors, they should be converted to explicit
   * error checks and handled gracefully.
   */
  if (rupdate.rs_rpupd) {
      assert(rupdate.rs_rpupd == rupdate.last_rpupd);
      assert(rupdate.rs_rpupd->rp != NULL);
      assert(rupdate.rs_rpupd->rp->r_pub != NULL);
      assert(rupdate.rs_rpupd->rp->r_pub->endpoint == RS_PROC_NR);
      assert(!UPD_IS_PREPARING_ONLY(rupdate.rs_rpupd));
  }
  if (rupdate.vm_rpupd) {
      assert(rupdate.vm_rpupd->rp != NULL);
      assert(rupdate.vm_rpupd->rp->r_pub != NULL);
      assert(rupdate.vm_rpupd->rp->r_pub->endpoint == VM_PROC_NR);
      assert(!UPD_IS_PREPARING_ONLY(rupdate.vm_rpupd));
  }

  /* If a multi-component update includes VM, fill information about old and new
   * endpoints, as well as update flags. VM needs this to complete the update
   * internally at state transfer time.
   */
  if (RUPDATE_IS_UPD_VM_MULTI()) {
      RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
          if (!UPD_IS_PREPARING_ONLY(rpupd)) {
              rp = rpupd->rp;
              /* Assert essential pointers are valid for non-preparing-only updates.
               * These are assumed to be invariants as per original code.
               */
              assert(rp != NULL);
              assert(rp->r_new_rp != NULL);
              assert(rp->r_pub != NULL);

              new_rp = rp->r_new_rp; // Assignment here for consistency, though unused in original.

              rp->r_pub->old_endpoint = rpupd->state_endpoint;
              rp->r_pub->new_endpoint = rp->r_pub->endpoint;

              /* Apply VM-specific flags to components other than VM itself or RS. */
              if (rpupd != rupdate.vm_rpupd && rpupd != rupdate.rs_rpupd) {
                  rp->r_pub->sys_flags |= SF_VM_UPDATE;
                  if (rpupd->lu_flags & SEF_LU_NOMMAP) {
                      rp->r_pub->sys_flags |= SF_VM_NOMMAP;
                  }
              }
          }
      );
  }

  /* Request the first service to prepare for the update.
   * If start_update_prepare_next() returns NULL, it implies all necessary
   * preparations are completed.
   */
  if (start_update_prepare_next() == NULL) {
      /* The preparation phase is complete, finalize the update with an OK status.
       * Returning ESRCH (No such process) might signify "no more processes to
       * update" in this context, rather than a true error.
       */
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
  struct rprocupd *rpupd_current, *prev_rpupd, *walk_rpupd;
  struct rproc *rp, *new_rp;

  if(!RUPDATE_IS_UPDATING()) {
      rpupd_current = rupdate.first_rpupd;
  }
  else {
      rpupd_current = rupdate.curr_rpupd->next_rpupd;
  }

  if(!rpupd_current) {
      return NULL;
  }

  if (RUPDATE_IS_UPD_VM_MULTI() && rpupd_current == rupdate.vm_rpupd) {
      RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, walk_rpupd,
          if (UPD_IS_PREPARING_ONLY(walk_rpupd))
              continue;
          if (walk_rpupd == rupdate.vm_rpupd)
              continue;
          rp = walk_rpupd->rp;
          new_rp = rp->r_new_rp;
          assert(rp && new_rp);
          if (rs_verbose)
              printf("RS: preparing VM for %s -> %s\n", srv_to_string(rp),
                srv_to_string(new_rp));
          vm_prepare(rp->r_pub->new_endpoint, new_rp->r_pub->endpoint,
            rp->r_pub->sys_flags);
      );
  }

  rupdate.flags |= RS_UPDATING;

  while(1) {
      rupdate.curr_rpupd = rpupd_current;
      request_prepare_update_service(rupdate.curr_rpupd->rp, rupdate.curr_rpupd->prepare_state);

      if(!UPD_IS_PREPARING_ONLY(rpupd_current)) {
          break;
      }
      if(!rupdate.curr_rpupd->next_rpupd) {
          break;
      }
      rpupd_current = rupdate.curr_rpupd->next_rpupd;
  }

  return rpupd_current;
}

/*===========================================================================*
 *				start_update				     *
 *===========================================================================*/
int start_update()
{
  struct rprocupd *prev_rpupd = NULL;
  struct rprocupd *rpupd = NULL;
  int r = OK;
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
  );

  if (!init_ready_pending) {
      end_update(OK, 0);
      return OK;
  }

  if (RUPDATE_IS_UPD_VM_MULTI()) {
      message m;
      int vm_receive_status = OK;
      int vm_init_final_result = OK;

      if (rs_verbose) {
          printf("RS: waiting for VM to initialize...\n");
      }

      m.m_source = VM_PROC_NR;
      m.m_type = RS_INIT;
      m.m_rs_init.result = EINTR;

      vm_receive_status = rs_receive_ticks(VM_PROC_NR, &m, NULL, UPD_INIT_MAXTIME(rupdate.vm_rpupd));

      if (vm_receive_status != OK) {
          vm_init_final_result = vm_receive_status;
      } else if (m.m_type != RS_INIT) {
          m.m_rs_init.result = EINTR;
          vm_init_final_result = EINTR;
      } else {
          vm_init_final_result = m.m_rs_init.result;
      }
      
      do_init_ready(&m);

      if (vm_init_final_result == OK) {
          m.m_type = OK;
          m.m_rs_init.result = OK;
          reply(VM_PROC_NR, NULL, &m);

          RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
              if (!UPD_IS_PREPARING_ONLY(rpupd) && rpupd != rupdate.vm_rpupd) {
                  r = complete_srv_update(rpupd);
                  if (r != OK) {
                      return r;
                  }
              }
          );
      } else {
          return vm_init_final_result;
      }
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
  int r;
  int sys_upd_flags = 0;

  assert(old_rp && new_rp);

  if(rs_verbose)
      printf("RS: %s starting the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));

  rupdate.num_init_ready_pending++;
  new_rp->r_flags |= (RS_INITIALIZING | RS_INIT_PENDING);
  
  if(rpupd->lu_flags & SEF_LU_NOMMAP) {
      sys_upd_flags |= SF_VM_NOMMAP;
  }

  if(old_rp->r_pub->endpoint != RS_PROC_NR) {
      r = update_service(&old_rp, &new_rp, RS_SWAP, sys_upd_flags);
      if(r != OK) {
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
  struct rproc *old_rp;
  struct rproc *new_rp;
  int r;

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;

  assert(old_rp != NULL);
  assert(new_rp != NULL);

  if (rs_verbose) {
      printf("RS: %s completing the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));
  }

  new_rp->r_flags &= ~RS_INIT_PENDING;

  if (old_rp->r_pub->endpoint == RS_PROC_NR) {
      r = init_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
      if (r != OK) {
          panic("RS update: unable to initialize new RS instance (error: %d)", r);
      }

      if (rs_verbose) {
          printf("RS: %s is the new RS instance we'll yield control to\n", srv_to_string(new_rp));
      }

      r = sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_YIELD, NULL);
      if (r != OK) {
          panic("RS update: unable to yield control to new RS instance (error: %d)", r);
      }
      
      return OK;
  }

  r = run_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
  if (r != OK) {
      rollback_service(&new_rp, &old_rp);
      end_update(r, RS_REPLY);
      
      if (rs_verbose) {
          printf("RS: update failed for %s: error %d\n", srv_to_string(old_rp), r);
      } else {
          printf("RS: update failed: error %d\n", r);
      }
      return r;
  }

  return OK;
}

/*===========================================================================*
 *			    abort_update_proc				     *
 *===========================================================================*/
int abort_update_proc(int reason)
{
  if (reason == OK) {
    return EINVAL;
  }

  int is_updating = RUPDATE_IS_UPDATING();
  int is_scheduled = RUPDATE_IS_UPD_SCHEDULED();

  if (!is_updating && !is_scheduled) {
    return EINVAL;
  }

  if (rs_verbose) {
    const char* update_state_str = is_updating ? "in-progress" : "scheduled";
    printf("RS: aborting the %s update process prematurely\n", update_state_str);
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
  struct rproc *old_rp, *new_rp;

  assert(rpupd != NULL);
  assert(rpupd == rupdate.curr_rpupd);

  old_rp = rpupd->rp;
  assert(old_rp != NULL);

  new_rp = old_rp->r_new_rp;
  assert(new_rp != NULL);
  
  if(result != OK && SRV_IS_UPDATING_AND_INITIALIZING(new_rp) && rpupd != rupdate.rs_rpupd) {
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

  assert(result != OK);
  assert(rpupd != NULL);

  old_rp = rpupd->rp;
  assert(old_rp != NULL);

  new_rp = old_rp->r_new_rp;
  assert(new_rp != NULL);

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

  if (result == OK) {
    return;
  }

  if (RUPDATE_IS_INITIALIZING()) {
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
  struct rproc *old_rp;
  struct rproc *new_rp;

  old_rp = rpupd->rp;
  assert(old_rp);
  new_rp = old_rp->r_new_rp;
  assert(new_rp);

  assert(SRV_IS_UPDATING_AND_INITIALIZING(new_rp));

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
  short is_after_curr;

  is_after_curr = 1;

  RUPDATE_REV_ITER(rupdate.last_rpupd, prev_rpupd, rpupd,
      short is_current_rpupd = (rupdate.curr_rpupd == rpupd);
      
      is_after_curr = is_after_curr && !is_current_rpupd;

      if (UPD_IS_PREPARING_ONLY(rpupd)) {
          continue;
      }

      if (skip_rpupd && rpupd == skip_rpupd) {
          continue;
      }
      if (only_rpupd && rpupd != only_rpupd) {
          continue;
      }

      if (is_current_rpupd) {
          end_update_curr(rpupd, result, reply_flag);
      } else if (RUPDATE_IS_INITIALIZING()) {
          if (is_after_curr) {
              end_update_prepare_done(rpupd, result);
          } else {
              end_update_initializing(rpupd, result);
          }
      } else {
          if (is_after_curr) {
              end_update_before_prepare(rpupd, result);
          } else {
              end_update_prepare_done(rpupd, result);
          }
      }
  );
}

/*===========================================================================*
 *			    end_update_debug				     *
 *===========================================================================*/
void end_update_debug(char *file, int line, int result, int reply_flag) {
    struct rprocupd *prev_rpupd;
    struct rprocupd *rpupd;
    struct rproc *rp;
    struct rproc *new_rp;
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

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd, {
        if (UPD_IS_PREPARING_ONLY(rpupd)) {
            if (!RUPDATE_IS_INITIALIZING()) {
                request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
            }
            rpupd->rp->r_flags &= ~RS_PREPARE_DONE;
        }
    });

    end_update_rev_iter(result, reply_flag, rupdate.vm_rpupd, NULL);
    if (rupdate.vm_rpupd != NULL) {
        end_update_rev_iter(result, reply_flag, NULL, rupdate.vm_rpupd);
    }

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd, {
        if (prev_rpupd != NULL) {
            rupdate_upd_clear(prev_rpupd);
        }

        if (result == OK && !UPD_IS_PREPARING_ONLY(rpupd)) {
            new_rp = rpupd->rp;
            end_srv_init(new_rp);
        }
    });

    if (rupdate.last_rpupd != NULL) {
        late_reply(rupdate.last_rpupd->rp, result);
        rupdate_upd_clear(rupdate.last_rpupd);
    }
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
  struct rproc *old_rp;
  struct rproc *new_rp;
  struct rproc *exiting_rp;
  struct rproc *surviving_rp;
  struct rproc **rps;
  int nr_rps;
  int i;

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  assert(old_rp != NULL && new_rp != NULL);

  if (result == OK && new_rp->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) {
      reply_flag = RS_CANCEL;
  }

  if (rs_verbose) {
      printf("RS: ending update from %s to %s with result=%d, reply=%d\n",
          srv_to_string(old_rp), srv_to_string(new_rp), result, (reply_flag == RS_REPLY));
  }

  surviving_rp = (result == OK ? new_rp : old_rp);
  exiting_rp =   (result == OK ? old_rp : new_rp);

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
  } else if (reply_flag == RS_CANCEL) {
      if (!(surviving_rp->r_flags & RS_TERMINATED)) {
          request_prepare_update_service(surviving_rp, SEF_LU_STATE_NULL);
      }
  }

  get_service_instances(exiting_rp, &rps, &nr_rps);

  const int is_detaching_old_rp_on_success = (result == OK && (rpupd->lu_flags & SEF_LU_DETACHED));

  for (i = 0; i < nr_rps; i++) {
      if (is_detaching_old_rp_on_success && rps[i] == old_rp) {
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
      printf("RS: %s ended the %s\n", srv_to_string(surviving_rp),
          srv_upd_to_string(rpupd));
  }
}

