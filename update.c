
#include "inc.h"

/*===========================================================================*
 *			      rupdate_clear_upds			     *
 *===========================================================================*/
void rupdate_clear_upds()
{
    clear_update_chain();
    clear_last_update();
    RUPDATE_CLEAR();
}

static void clear_update_chain()
{
    struct rprocupd *prev_rpupd, *rpupd;
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if(prev_rpupd) {
            rupdate_upd_clear(prev_rpupd);
        }
    );
}

static void clear_last_update()
{
    rupdate_upd_clear(rupdate.last_rpupd);
}

/*===========================================================================*
 *			       rupdate_add_upd  			     *
 *===========================================================================*/
void rupdate_add_upd(struct rprocupd* rpupd)
{
  struct rprocupd *prev_rpupd;
  endpoint_t ep;
  int lu_flags;

  ep = rpupd->rp->r_pub->endpoint;

  assert(rpupd->next_rpupd == NULL);
  assert(rpupd->prev_rpupd == NULL);

  prev_rpupd = find_insertion_point(ep);
  insert_update_descriptor(rpupd, prev_rpupd);
  rupdate.num_rpupds++;

  lu_flags = rpupd->lu_flags & (SEF_LU_INCLUDES_VM|SEF_LU_INCLUDES_RS|SEF_LU_MULTI);
  if(lu_flags) {
      propagate_flags(lu_flags);
  }

  update_special_descriptors(rpupd, lu_flags);
}

static struct rprocupd* find_insertion_point(endpoint_t ep)
{
  struct rprocupd *prev_rpupd = rupdate.last_rpupd;
  
  if (should_skip_rs_endpoint(prev_rpupd, ep)) {
      prev_rpupd = prev_rpupd->prev_rpupd;
  }
  if (should_skip_vm_endpoint(prev_rpupd, ep)) {
      prev_rpupd = prev_rpupd->prev_rpupd;
  }
  
  return prev_rpupd;
}

static int should_skip_rs_endpoint(struct rprocupd *prev_rpupd, endpoint_t ep)
{
  return prev_rpupd != NULL && 
         ep != RS_PROC_NR &&
         prev_rpupd->rp->r_pub->endpoint == RS_PROC_NR;
}

static int should_skip_vm_endpoint(struct rprocupd *prev_rpupd, endpoint_t ep)
{
  return prev_rpupd != NULL && 
         ep != RS_PROC_NR && 
         ep != VM_PROC_NR &&
         prev_rpupd->rp->r_pub->endpoint == VM_PROC_NR;
}

static void insert_update_descriptor(struct rprocupd *rpupd, struct rprocupd *prev_rpupd)
{
  if (prev_rpupd == NULL) {
      insert_at_head(rpupd);
  } else {
      insert_after(rpupd, prev_rpupd);
  }
  
  update_chain_pointers(rpupd);
}

static void insert_at_head(struct rprocupd *rpupd)
{
  rpupd->next_rpupd = rupdate.first_rpupd;
  rupdate.first_rpupd = rupdate.curr_rpupd = rpupd;
}

static void insert_after(struct rprocupd *rpupd, struct rprocupd *prev_rpupd)
{
  rpupd->next_rpupd = prev_rpupd->next_rpupd;
  rpupd->prev_rpupd = prev_rpupd;
  prev_rpupd->next_rpupd = rpupd;
}

static void update_chain_pointers(struct rprocupd *rpupd)
{
  if (rpupd->next_rpupd != NULL) {
      rpupd->next_rpupd->prev_rpupd = rpupd;
  } else {
      rupdate.last_rpupd = rpupd;
  }
}

static void propagate_flags(int lu_flags)
{
  struct rprocupd *prev_rpupd, *walk_rpupd;
  
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, walk_rpupd,
      walk_rpupd->lu_flags |= lu_flags;
      walk_rpupd->init_flags |= lu_flags;
  );
}

static void update_special_descriptors(struct rprocupd *rpupd, int lu_flags)
{
  if(!rupdate.vm_rpupd && (lu_flags & SEF_LU_INCLUDES_VM)) {
      rupdate.vm_rpupd = rpupd;
  }
  else if(!rupdate.rs_rpupd && (lu_flags & SEF_LU_INCLUDES_RS)) {
      rupdate.rs_rpupd = rpupd;
  }
}

/*===========================================================================*
 *			  rupdate_set_new_upd_flags  			     *
 *===========================================================================*/
void rupdate_set_new_upd_flags(struct rprocupd* rpupd)
{
    set_multi_component_flags(rpupd);
    propagate_flags_from_last_service(rpupd);
    
    if(UPD_IS_PREPARING_ONLY(rpupd)) {
        return;
    }
    
    set_vm_rs_flags(rpupd);
}

static void set_multi_component_flags(struct rprocupd* rpupd)
{
    if(rupdate.num_rpupds > 0) {
        apply_flags(rpupd, SEF_LU_MULTI);
    }
}

static void propagate_flags_from_last_service(struct rprocupd* rpupd)
{
    if(rupdate.last_rpupd) {
        int lu_flags = rupdate.last_rpupd->lu_flags & (SEF_LU_INCLUDES_VM|SEF_LU_INCLUDES_RS);
        apply_flags(rpupd, lu_flags);
    }
}

static void set_vm_rs_flags(struct rprocupd* rpupd)
{
    int endpoint = rpupd->rp->r_pub->endpoint;
    
    if(endpoint == VM_PROC_NR) {
        apply_flags(rpupd, SEF_LU_INCLUDES_VM);
    }
    else if(endpoint == RS_PROC_NR) {
        apply_flags(rpupd, SEF_LU_INCLUDES_RS);
    }
}

static void apply_flags(struct rprocupd* rpupd, int flags)
{
    rpupd->lu_flags |= flags;
    rpupd->init_flags |= flags;
}

/*===========================================================================*
 *			      rupdate_upd_init  			     *
 *===========================================================================*/
void rupdate_upd_init(struct rprocupd* rpupd, struct rproc *rp)
{
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
    if(rpupd->rp->r_new_rp) {
        cleanup_service(rpupd->rp->r_new_rp);
    }
    
    if(rpupd->prepare_state_data_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data_gid);
    }
    
    revoke_prepare_state_grants(rpupd);
    free_prepare_state_memory(rpupd);
    
    rupdate_upd_init(rpupd, NULL);
}

static void revoke_prepare_state_grants(struct rprocupd* rpupd)
{
    if(rpupd->prepare_state_data.size <= 0) {
        return;
    }
    
    if(rpupd->prepare_state_data.ipcf_els_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data.ipcf_els_gid);
    }
    
    if(rpupd->prepare_state_data.eval_gid != GRANT_INVALID) {
        cpf_revoke(rpupd->prepare_state_data.eval_gid);
    }
}

static void free_prepare_state_memory(struct rprocupd* rpupd)
{
    if(rpupd->prepare_state_data.size <= 0) {
        return;
    }
    
    if(rpupd->prepare_state_data.ipcf_els) {
        free(rpupd->prepare_state_data.ipcf_els);
    }
    
    if(rpupd->prepare_state_data.eval_addr) {
        free(rpupd->prepare_state_data.eval_addr);
    }
}

/*===========================================================================*
 *			       rupdate_upd_move 			     *
 *===========================================================================*/
void rupdate_upd_move(struct rproc* src_rp, struct rproc* dst_rp)
{
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
  struct rprocpub *rpub;
  int no_reply;

  rpub = rp->r_pub;

  if(state != SEF_LU_STATE_NULL) {
      prepare_update_request(rp, &m, state, file, line);
  }
  else {
      prepare_cancel_request(rp, file, line);
  }

  m.m_type = RS_LU_PREPARE;
  m.m_rs_update.state = state;
  no_reply = !(rp->r_flags & RS_PREPARE_DONE);
  rs_asynsend(rp, &m, no_reply);
}

static void prepare_update_request(struct rproc *rp, message *m, int state, char *file, int line)
{
  struct rprocupd *rpupd = &rp->r_upd;
  rpupd->prepare_tm = getticks();
  
  set_updating_flags(rp, rpupd);
  
  m->m_rs_update.flags = rpupd->lu_flags;
  m->m_rs_update.state_data_gid = rpupd->prepare_state_data_gid;

  log_prepare_request(rp, rpupd, file, line);
}

static void set_updating_flags(struct rproc *rp, struct rprocupd *rpupd)
{
  if(!UPD_IS_PREPARING_ONLY(rpupd)) {
      assert(rp->r_new_rp);
      rp->r_flags |= RS_UPDATING;
      rp->r_new_rp->r_flags |= RS_UPDATING;
  }
  else {
      assert(!rp->r_new_rp);
  }
}

static void log_prepare_request(struct rproc *rp, struct rprocupd *rpupd, char *file, int line)
{
  if(rs_verbose) {
      printf("RS: %s being requested to prepare for the %s at %s:%d\n", 
          srv_to_string(rp), srv_upd_to_string(rpupd), file, line);
  }
}

static void prepare_cancel_request(struct rproc *rp, char *file, int line)
{
  if(rs_verbose) {
      printf("RS: %s being requested to cancel the update at %s:%d\n", 
          srv_to_string(rp), file, line);
  }
}

/*===========================================================================*
 *				 srv_update				     *
 *===========================================================================*/
int srv_update(endpoint_t src_e, endpoint_t dst_e, int sys_upd_flags)
{
    if (rs_verbose) {
        const char* action = (src_e == VM_PROC_NR) ? "executing sys_update" :
                           (!RUPDATE_IS_UPD_VM_MULTI() || RUPDATE_IS_VM_INIT_DONE()) ? "executing vm_update" :
                           "skipping srv_update";
        printf("RS: %s(%d, %d)\n", action, src_e, dst_e);
    }

    if (src_e == VM_PROC_NR) {
        int flags = (sys_upd_flags & SF_VM_ROLLBACK) ? SYS_UPD_ROLLBACK : 0;
        return sys_update(src_e, dst_e, flags);
    }
    
    if (!RUPDATE_IS_UPD_VM_MULTI() || RUPDATE_IS_VM_INIT_DONE()) {
        return vm_update(src_e, dst_e, sys_upd_flags);
    }
    
    return OK;
}

/*===========================================================================*
 *				update_service				     *
 *===========================================================================*/
int update_service(src_rpp, dst_rpp, swap_flag, sys_upd_flags)
struct rproc **src_rpp;
struct rproc **dst_rpp;
int swap_flag;
int sys_upd_flags;
{
  int r;
  struct rproc *src_rp;
  struct rproc *dst_rp;

  src_rp = *src_rpp;
  dst_rp = *dst_rpp;

  print_update_message(src_rp, dst_rp, "updating into");

  if(swap_flag == RS_SWAP) {
      r = perform_system_update(src_rp, dst_rp, sys_upd_flags);
      if(r != OK) {
          return r;
      }
  }

  perform_slot_swap(src_rp, dst_rp);
  
  r = update_privileges(src_rp, dst_rp);
  if(r != OK) {
      return r;
  }

  *src_rpp = src_rp;
  *dst_rpp = dst_rp;

  activate_service(dst_rp, src_rp);

  print_update_message(src_rp, dst_rp, "updated into");

  return OK;
}

static void print_update_message(src_rp, dst_rp, action)
struct rproc *src_rp;
struct rproc *dst_rp;
char *action;
{
  if(rs_verbose) {
      printf("RS: %s %s %s\n",
          srv_to_string(src_rp), action, srv_to_string(dst_rp));
  }
}

static int perform_system_update(src_rp, dst_rp, sys_upd_flags)
struct rproc *src_rp;
struct rproc *dst_rp;
int sys_upd_flags;
{
  return srv_update(src_rp->r_pub->endpoint, dst_rp->r_pub->endpoint, sys_upd_flags);
}

static void perform_slot_swap(src_rp, dst_rp)
struct rproc *src_rp;
struct rproc *dst_rp;
{
  int pid;
  endpoint_t endpoint;

  pid = src_rp->r_pid;
  endpoint = src_rp->r_pub->endpoint;

  swap_slot(&src_rp, &dst_rp);

  reassign_process_data(src_rp, dst_rp->r_pid, dst_rp->r_pub->endpoint);
  reassign_process_data(dst_rp, pid, endpoint);
}

static void reassign_process_data(rp, pid, endpoint)
struct rproc *rp;
int pid;
endpoint_t endpoint;
{
  rp->r_pid = pid;
  rp->r_pub->endpoint = endpoint;
  rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = rp;
}

static int update_privileges(src_rp, dst_rp)
struct rproc *src_rp;
struct rproc *dst_rp;
{
  int r;
  
  r = update_single_privilege(src_rp, "src");
  if(r != OK) {
      return r;
  }
  
  r = update_single_privilege(dst_rp, "dst");
  return r;
}

static int update_single_privilege(rp, label)
struct rproc *rp;
char *label;
{
  int r;
  
  r = sys_getpriv(&rp->r_priv, rp->r_pub->endpoint);
  if(r != OK) {
      panic("RS: update: could not update RS copies of priv of %s: %d\n", label, r);
  }
  return r;
}

/*===========================================================================*
 *			      rollback_service				     *
 *===========================================================================*/
void rollback_service(struct rproc **new_rpp, struct rproc **old_rpp)
{
    if((*old_rpp)->r_pub->endpoint == RS_PROC_NR) {
        handle_rs_rollback(new_rpp, old_rpp);
    }
    else {
        handle_regular_rollback(new_rpp, old_rpp);
    }
}

static void handle_rs_rollback(struct rproc **new_rpp, struct rproc **old_rpp)
{
    if(!is_rs_process()) {
        perform_vm_rollback(*new_rpp, *old_rpp);
    }
    reset_heartbeat_timers();
}

static int is_rs_process(void)
{
    endpoint_t me = NONE;
    char name[20];
    int priv_flags, init_flags;
    int r = sys_whoami(&me, name, sizeof(name), &priv_flags, &init_flags);
    assert(r == OK);
    return (me == RS_PROC_NR);
}

static void perform_vm_rollback(struct rproc *new_rp, struct rproc *old_rp)
{
    int r = vm_update(new_rp->r_pub->endpoint, old_rp->r_pub->endpoint, SF_VM_ROLLBACK);
    if(rs_verbose) {
        printf("RS: %s performed rollback\n", srv_to_string(new_rp));
    }
}

static void reset_heartbeat_timers(void)
{
    struct rproc *rp;
    for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        if (rp->r_flags & RS_ACTIVE) {
            rp->r_check_tm = 0;
        }
    }
}

static void handle_regular_rollback(struct rproc **new_rpp, struct rproc **old_rpp)
{
    int swap_flag = determine_swap_flag(*new_rpp);
    
    if(rs_verbose) {
        printf("RS: %s performs rollback\n", srv_to_string(*new_rpp));
    }
    
    if(swap_flag == RS_SWAP) {
        freeze_new_instance(*new_rpp);
    }
    
    int r = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
    assert(r == OK);
}

static int determine_swap_flag(struct rproc *rp)
{
    return (rp->r_flags & RS_INIT_PENDING) ? RS_DONTSWAP : RS_SWAP;
}

static void freeze_new_instance(struct rproc *rp)
{
    sys_privctl(rp->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
}

/*===========================================================================*
 *				update_period				     *
 *===========================================================================*/
#define UPDATE_TIMEOUT_OCCURRED(rpupd, now) \
    ((rpupd)->prepare_maxtime > 0 && (now) - (rpupd)->prepare_tm > (rpupd)->prepare_maxtime)

void update_period(message *m_ptr)
{
  clock_t now = m_ptr->m_notify.timestamp;
  message m;
  struct rprocupd *rpupd = rupdate.curr_rpupd;
  struct rproc *rp = rpupd->rp;
  struct rprocpub *rpub = rp->r_pub;

  if(UPDATE_TIMEOUT_OCCURRED(rpupd, now)) {
      printf("RS: update failed: maximum prepare time reached\n");
      end_update(EINTR, RS_CANCEL);
  }
}

/*===========================================================================*
 *			    start_update_prepare			     *
 *===========================================================================*/
int start_update_prepare(int allow_retries)
{
  struct rprocupd *prev_rpupd, *rpupd;
  struct rproc *rp, *new_rp;
  int r;

  if(!RUPDATE_IS_UPD_SCHEDULED()) {
      return EINVAL;
  }
  
  if(!rs_is_idle()) {
      return handle_not_idle(allow_retries);
  }

  if(rs_verbose)
      printf("RS: starting the preparation phase of the update process\n");

  validate_rs_rpupd();
  validate_vm_rpupd();
  
  if(RUPDATE_IS_UPD_VM_MULTI()) {
      setup_vm_multi_update();
  }

  if(start_update_prepare_next() == NULL) {
      end_update(OK, RS_REPLY);
      return ESRCH;
  }

  return OK;
}

static int handle_not_idle(int allow_retries)
{
  printf("RS: not idle now, try again\n");
  if(!allow_retries) {
      abort_update_proc(EAGAIN);
  }
  return EAGAIN;
}

static void validate_rs_rpupd(void)
{
  if(rupdate.rs_rpupd) {
      assert(rupdate.rs_rpupd == rupdate.last_rpupd);
      assert(rupdate.rs_rpupd->rp->r_pub->endpoint == RS_PROC_NR);
      assert(!UPD_IS_PREPARING_ONLY(rupdate.rs_rpupd));
  }
}

static void validate_vm_rpupd(void)
{
  if(rupdate.vm_rpupd) {
      assert(rupdate.vm_rpupd->rp->r_pub->endpoint == VM_PROC_NR);
      assert(!UPD_IS_PREPARING_ONLY(rupdate.vm_rpupd));
  }
}

static void setup_vm_multi_update(void)
{
  struct rprocupd *prev_rpupd, *rpupd;
  
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
      if(!UPD_IS_PREPARING_ONLY(rpupd)) {
          setup_single_vm_update(rpupd);
      }
  );
}

static void setup_single_vm_update(struct rprocupd *rpupd)
{
  struct rproc *rp = rpupd->rp;
  struct rproc *new_rp = rp->r_new_rp;
  
  assert(rp && new_rp);
  rp->r_pub->old_endpoint = rpupd->state_endpoint;
  rp->r_pub->new_endpoint = rp->r_pub->endpoint;
  
  if(rpupd != rupdate.vm_rpupd && rpupd != rupdate.rs_rpupd) {
      set_vm_update_flags(rp, rpupd);
  }
}

static void set_vm_update_flags(struct rproc *rp, struct rprocupd *rpupd)
{
  rp->r_pub->sys_flags |= SF_VM_UPDATE;
  if(rpupd->lu_flags & SEF_LU_NOMMAP) {
      rp->r_pub->sys_flags |= SF_VM_NOMMAP;
  }
}

/*===========================================================================*
 *			  start_update_prepare_next			     *
 *===========================================================================*/
struct rprocupd* get_next_rpupd()
{
    if (!RUPDATE_IS_UPDATING()) {
        return rupdate.first_rpupd;
    }
    return rupdate.curr_rpupd->next_rpupd;
}

void prepare_vm_for_service(struct rprocupd *walk_rpupd)
{
    struct rproc *rp, *new_rp;
    
    if (UPD_IS_PREPARING_ONLY(walk_rpupd)) {
        return;
    }
    if (walk_rpupd == rupdate.vm_rpupd) {
        return;
    }
    
    rp = walk_rpupd->rp;
    new_rp = rp->r_new_rp;
    assert(rp && new_rp);
    
    if (rs_verbose) {
        printf("RS: preparing VM for %s -> %s\n", 
               srv_to_string(rp), srv_to_string(new_rp));
    }
    
    vm_prepare(rp->r_pub->new_endpoint, 
               new_rp->r_pub->endpoint,
               rp->r_pub->sys_flags);
}

void prepare_vm_for_all_services()
{
    struct rprocupd *prev_rpupd, *walk_rpupd;
    
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, walk_rpupd,
        prepare_vm_for_service(walk_rpupd);
    );
}

int should_prepare_vm(struct rprocupd *rpupd)
{
    return RUPDATE_IS_UPD_VM_MULTI() && rpupd == rupdate.vm_rpupd;
}

struct rprocupd* process_prepare_only_services(struct rprocupd *rpupd)
{
    while (1) {
        rupdate.curr_rpupd = rpupd;
        request_prepare_update_service(rupdate.curr_rpupd->rp, 
                                      rupdate.curr_rpupd->prepare_state);
        
        if (!UPD_IS_PREPARING_ONLY(rpupd)) {
            break;
        }
        if (!rupdate.curr_rpupd->next_rpupd) {
            break;
        }
        rpupd = rupdate.curr_rpupd->next_rpupd;
    }
    return rpupd;
}

struct rprocupd* start_update_prepare_next()
{
    struct rprocupd *rpupd;
    
    rpupd = get_next_rpupd();
    if (!rpupd) {
        return NULL;
    }
    
    if (should_prepare_vm(rpupd)) {
        prepare_vm_for_all_services();
    }
    
    rupdate.flags |= RS_UPDATING;
    
    return process_prepare_only_services(rpupd);
}

/*===========================================================================*
 *				start_update				     *
 *===========================================================================*/
#define UPD_INIT_MAXTIME_DEFAULT 3000
#define RS_INIT_SUCCESS OK

static void cancel_prepare_only_services(void)
{
    struct rprocupd *prev_rpupd, *rpupd;
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if(UPD_IS_PREPARING_ONLY(rpupd)) {
            request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
        }
    );
}

static int start_and_complete_service_update(struct rprocupd *rpupd)
{
    int r = start_srv_update(rpupd);
    if(r != OK) {
        return r;
    }
    
    if(!RUPDATE_IS_UPD_VM_MULTI() || rpupd == rupdate.vm_rpupd) {
        r = complete_srv_update(rpupd);
    }
    return r;
}

static int update_services(void)
{
    struct rprocupd *prev_rpupd, *rpupd;
    int init_ready_pending = 0;
    int r;
    
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        rupdate.curr_rpupd = rpupd;
        if(!UPD_IS_PREPARING_ONLY(rpupd)) {
            init_ready_pending = 1;
            r = start_and_complete_service_update(rpupd);
            if(r != OK) {
                return r;
            }
        }
    );
    
    if(!init_ready_pending) {
        end_update(OK, 0);
        return OK;
    }
    
    return init_ready_pending;
}

static int wait_for_vm_initialization(message *m)
{
    if(rs_verbose) {
        printf("RS: waiting for VM to initialize...\n");
    }
    
    int r = rs_receive_ticks(VM_PROC_NR, m, NULL, UPD_INIT_MAXTIME(rupdate.vm_rpupd));
    
    if(r != OK || m->m_type != RS_INIT || m->m_rs_init.result != OK) {
        r = (r == OK && m->m_type == RS_INIT ? m->m_rs_init.result : EINTR);
        m->m_source = VM_PROC_NR;
        m->m_type = RS_INIT;
        m->m_rs_init.result = r;
    }
    
    return r;
}

static int complete_remaining_updates(void)
{
    struct rprocupd *prev_rpupd, *rpupd;
    int r;
    
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        if(!UPD_IS_PREPARING_ONLY(rpupd) && rpupd != rupdate.vm_rpupd) {
            r = complete_srv_update(rpupd);
            if(r != OK) {
                return r;
            }
        }
    );
    
    return OK;
}

static int handle_vm_multi_update(void)
{
    message m;
    int r = wait_for_vm_initialization(&m);
    
    do_init_ready(&m);
    
    if(r == RS_INIT_SUCCESS) {
        m.m_type = OK;
        reply(VM_PROC_NR, NULL, &m);
        return complete_remaining_updates();
    }
    
    return OK;
}

static void print_update_start(void)
{
    if(rs_verbose) {
        printf("RS: starting a %s-component update process\n",
            RUPDATE_IS_UPD_MULTI() ? "multi" : "single");
    }
}

static void validate_update_state(void)
{
    assert(RUPDATE_IS_UPDATING());
    assert(rupdate.num_rpupds > 0);
    assert(rupdate.num_init_ready_pending == 0);
    assert(rupdate.first_rpupd);
    assert(rupdate.last_rpupd);
    assert(rupdate.curr_rpupd == rupdate.last_rpupd);
}

int start_update(void)
{
    int update_result;
    
    print_update_start();
    validate_update_state();
    
    rupdate.flags |= RS_INITIALIZING;
    
    cancel_prepare_only_services();
    
    update_result = update_services();
    if(update_result <= 0) {
        return update_result;
    }
    
    if(RUPDATE_IS_UPD_VM_MULTI()) {
        return handle_vm_multi_update();
    }
    
    return OK;
}

/*===========================================================================*
 *			      start_srv_update				     *
 *===========================================================================*/
int start_srv_update(struct rprocupd *rpupd)
{
    struct rproc *old_rp, *new_rp;
    int sys_upd_flags = 0;

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);

    if(rs_verbose)
        printf("RS: %s starting the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));

    initialize_new_service(new_rp);
    
    if(rpupd->lu_flags & SEF_LU_NOMMAP) {
        sys_upd_flags |= SF_VM_NOMMAP;
    }

    return perform_service_update(old_rp, new_rp, sys_upd_flags);
}

static void initialize_new_service(struct rproc *new_rp)
{
    rupdate.num_init_ready_pending++;
    new_rp->r_flags |= RS_INITIALIZING;
    new_rp->r_flags |= RS_INIT_PENDING;
}

static int perform_service_update(struct rproc *old_rp, struct rproc *new_rp, int sys_upd_flags)
{
    int r;
    
    if(old_rp->r_pub->endpoint == RS_PROC_NR) {
        return OK;
    }
    
    r = update_service(&old_rp, &new_rp, RS_SWAP, sys_upd_flags);
    if(r != OK) {
        end_update(r, RS_REPLY);
        printf("RS: update failed: error %d\n", r);
    }
    
    return r;
}

/*===========================================================================*
 *			   complete_srv_update				     *
 *===========================================================================*/
int complete_srv_update(struct rprocupd *rpupd)
{
  struct rproc *old_rp, *new_rp;
  int r;

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  assert(old_rp && new_rp);

  if(rs_verbose)
      printf("RS: %s completing the %s\n", srv_to_string(old_rp), srv_upd_to_string(rpupd));

  new_rp->r_flags &= ~RS_INIT_PENDING;

  if(old_rp->r_pub->endpoint == RS_PROC_NR) {
      return handle_rs_self_update(new_rp, old_rp, rpupd);
  }

  r = run_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
  if(r != OK) {
      perform_rollback(new_rp, old_rp, r);
      printf("RS: update failed: error %d\n", r);
      return r;
  }

  return OK;
}

static int handle_rs_self_update(struct rproc *new_rp, struct rproc *old_rp, struct rprocupd *rpupd)
{
  int r;

  r = init_service(new_rp, SEF_INIT_LU, rpupd->init_flags);
  if(r != OK) {
      panic("unable to initialize the new RS instance: %d", r);
  }

  if(rs_verbose)
      printf("RS: %s is the new RS instance we'll yield control to\n", srv_to_string(new_rp));

  r = sys_privctl(new_rp->r_pub->endpoint, SYS_PRIV_YIELD, NULL);
  if(r != OK) {
      panic("unable to yield control to the new RS instance: %d", r);
  }

  perform_rollback(new_rp, old_rp, ERESTART);
  printf("RS: update failed: state transfer failed for the new RS instance\n");
  return ERESTART;
}

static void perform_rollback(struct rproc *new_rp, struct rproc *old_rp, int error_code)
{
  rollback_service(&new_rp, &old_rp);
  end_update(error_code, RS_REPLY);
}

/*===========================================================================*
 *			    abort_update_proc				     *
 *===========================================================================*/
int abort_update_proc(int reason)
{
  int is_updating = RUPDATE_IS_UPDATING();
  assert(reason != OK);

  if(!is_updating && !RUPDATE_IS_UPD_SCHEDULED()) {
      return EINVAL;
  }

  if(rs_verbose)
      printf("RS: aborting the %s update process prematurely\n",
          is_updating ? "in-progress" : "scheduled");

  if(!is_updating) {
      rupdate_clear_upds();
      return OK;
  }

  int end_update_flag = (rupdate.flags & RS_INITIALIZING) ? RS_REPLY : RS_CANCEL;
  end_update(reason, end_update_flag);

  return OK;
}

/*===========================================================================*
 *			    end_update_curr				     *
 *===========================================================================*/
static void end_update_curr(struct rprocupd *rpupd, int result, int reply_flag)
{
  struct rproc *old_rp, *new_rp;
  assert(rpupd == rupdate.curr_rpupd);

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  assert(old_rp && new_rp);
  
  if(should_rollback(result, new_rp, rpupd)) {
      rollback_service(&new_rp, &old_rp);
  }
  end_srv_update(rpupd, result, reply_flag);
}

static int should_rollback(int result, struct rproc *new_rp, struct rprocupd *rpupd)
{
  return result != OK && 
         SRV_IS_UPDATING_AND_INITIALIZING(new_rp) && 
         rpupd != rupdate.rs_rpupd;
}

/*===========================================================================*
 *			end_update_before_prepare			     *
 *===========================================================================*/
static void end_update_before_prepare(struct rprocupd *rpupd, int result)
{
  struct rproc *old_rp, *new_rp;
  assert(result != OK);

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  assert(old_rp && new_rp);
  cleanup_service(new_rp);
}

/*===========================================================================*
 *			 end_update_prepare_done			     *
 *===========================================================================*/
static void end_update_prepare_done(struct rprocupd *rpupd, int result)
{
  assert(!RUPDATE_IS_INITIALIZING());
  assert(result != OK);
  assert(!(rpupd->rp->r_flags & RS_INITIALIZING));

  end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			 end_update_initializing			     *
 *===========================================================================*/
static void handle_initialization_failure(struct rproc **new_rp, struct rproc **old_rp, struct rprocupd *rpupd)
{
    if (rpupd != rupdate.rs_rpupd) {
        rollback_service(new_rp, old_rp);
    }
}

static void end_update_initializing(struct rprocupd *rpupd, int result)
{
    struct rproc *old_rp, *new_rp;

    old_rp = rpupd->rp;
    new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);
    assert(SRV_IS_UPDATING_AND_INITIALIZING(new_rp));
    
    if (result != OK) {
        handle_initialization_failure(&new_rp, &old_rp, rpupd);
    }
    
    end_srv_update(rpupd, result, RS_REPLY);
}

/*===========================================================================*
 *			    end_update_rev_iter				     *
 *===========================================================================*/
static int should_process_rpupd(struct rprocupd *rpupd, struct rprocupd *skip_rpupd, struct rprocupd *only_rpupd)
{
    return (!skip_rpupd || rpupd != skip_rpupd) && (!only_rpupd || rpupd == only_rpupd);
}

static void determine_update_phases(short is_curr, short is_after_curr, 
    short *is_before_prepare, short *is_prepare_done, short *is_initializing)
{
    short is_before_curr = !is_curr && !is_after_curr;
    
    if(RUPDATE_IS_INITIALIZING()) {
        *is_before_prepare = 0;
        *is_prepare_done = is_after_curr;
        *is_initializing = is_before_curr;
    }
    else {
        *is_before_prepare = is_after_curr;
        *is_prepare_done = is_before_curr;
        *is_initializing = 0;
    }
}

static void process_rpupd_update(struct rprocupd *rpupd, short is_curr, short is_after_curr,
    int result, int reply_flag)
{
    short is_before_prepare;
    short is_prepare_done;
    short is_initializing;
    
    determine_update_phases(is_curr, is_after_curr, 
        &is_before_prepare, &is_prepare_done, &is_initializing);
    
    if(is_curr) {
        end_update_curr(rpupd, result, reply_flag);
    }
    else if(is_before_prepare) {
        end_update_before_prepare(rpupd, result);
    }
    else if(is_prepare_done) {
        end_update_prepare_done(rpupd, result);
    }
    else {
        assert(is_initializing);
        end_update_initializing(rpupd, result);
    }
}

static void end_update_rev_iter(int result, int reply_flag,
    struct rprocupd *skip_rpupd, struct rprocupd *only_rpupd)
{
    struct rprocupd *prev_rpupd, *rpupd;
    short is_curr, is_after_curr;

    is_after_curr = 1;
    RUPDATE_REV_ITER(rupdate.last_rpupd, prev_rpupd, rpupd,
        is_curr = (rupdate.curr_rpupd == rpupd);
        is_after_curr = is_after_curr && !is_curr;
        
        if(!UPD_IS_PREPARING_ONLY(rpupd) && should_process_rpupd(rpupd, skip_rpupd, only_rpupd)) {
            process_rpupd_update(rpupd, is_curr, is_after_curr, result, reply_flag);
        }
    );
}

/*===========================================================================*
 *			    end_update_debug				     *
 *===========================================================================*/
void end_update_debug(char *file, int line,
    int result, int reply_flag)
{
  assert(RUPDATE_IS_UPDATING());

  log_update_ending(file, line, result, reply_flag);

  if(result != OK && RUPDATE_IS_RS_INIT_DONE()) {
      handle_failed_rs_update();
  }

  cancel_prepare_only_services();
  handle_remaining_services(result, reply_flag);
  complete_update_finalization(result);
  clear_system_update_flags();
}

static void log_update_ending(char *file, int line, int result, int reply_flag)
{
  if(rs_verbose) {
      printf("RS: %s ending the update: result=%d, reply=%d at %s:%d\n",
          srv_to_string(rupdate.curr_rpupd->rp), result, (reply_flag==RS_REPLY),
          file, line);
  }
}

static void handle_failed_rs_update(void)
{
  if(rs_verbose) {
      printf("RS: update failed, new RS instance will now exit\n");
  }
  exit(1);
}

static void cancel_prepare_only_services(void)
{
  struct rprocupd *prev_rpupd, *rpupd;
  
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
      if(UPD_IS_PREPARING_ONLY(rpupd)) {
          cancel_prepare_service(rpupd);
      }
  );
}

static void cancel_prepare_service(struct rprocupd *rpupd)
{
  if(!RUPDATE_IS_INITIALIZING()) {
      request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);
  }
  rpupd->rp->r_flags &= ~RS_PREPARE_DONE;
}

static void handle_remaining_services(int result, int reply_flag)
{
  end_update_rev_iter(result, reply_flag, rupdate.vm_rpupd, NULL);
  if(rupdate.vm_rpupd) {
      end_update_rev_iter(result, reply_flag, NULL, rupdate.vm_rpupd);
  }
}

static void complete_update_finalization(int result)
{
  struct rprocupd *prev_rpupd, *rpupd;
  
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
      finalize_single_update(prev_rpupd, rpupd, result);
  );
  
  late_reply(rupdate.last_rpupd->rp, result);
  rupdate_upd_clear(rupdate.last_rpupd);
  RUPDATE_CLEAR();
}

static void finalize_single_update(struct rprocupd *prev_rpupd, 
    struct rprocupd *rpupd, int result)
{
  if(prev_rpupd) {
      rupdate_upd_clear(prev_rpupd);
  }
  if(result == OK && !UPD_IS_PREPARING_ONLY(rpupd)) {
      end_srv_init(rpupd->rp);
  }
}

static void clear_system_update_flags(void)
{
  int slot_nr;
  struct rproc *rp;
  
  for(slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      rp = &rproc[slot_nr];
      clear_proc_update_flags(rp);
  }
}

static void clear_proc_update_flags(struct rproc *rp)
{
  rp->r_pub->old_endpoint = NONE;
  rp->r_pub->new_endpoint = NONE;
  rp->r_pub->sys_flags &= ~(SF_VM_UPDATE|SF_VM_ROLLBACK|SF_VM_NOMMAP);
}

/*===========================================================================*
*			      end_srv_update				     *
 *===========================================================================*/
void end_srv_update(struct rprocupd *rpupd, int result, int reply_flag)
{
  struct rproc *old_rp, *new_rp, *exiting_rp, *surviving_rp;
  struct rproc **rps;
  int nr_rps, i;

  old_rp = rpupd->rp;
  new_rp = old_rp->r_new_rp;
  assert(old_rp && new_rp);

  reply_flag = check_vm_update_multi(new_rp, result, reply_flag);
  log_update_end(old_rp, new_rp, result, reply_flag);

  determine_survivors(result, old_rp, new_rp, &surviving_rp, &exiting_rp);
  update_surviving_process(surviving_rp, rpupd);
  unlink_versions(old_rp, new_rp);
  handle_surviving_process_reply(surviving_rp, result, reply_flag);
  cleanup_exiting_version(exiting_rp, rpupd);

  log_update_completed(surviving_rp, rpupd);
}

static int check_vm_update_multi(struct rproc *new_rp, int result, int reply_flag)
{
  if(result == OK && new_rp->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) {
      return RS_CANCEL;
  }
  return reply_flag;
}

static void log_update_end(struct rproc *old_rp, struct rproc *new_rp, int result, int reply_flag)
{
  if(rs_verbose) {
      printf("RS: ending update from %s to %s with result=%d, reply=%d\n",
          srv_to_string(old_rp), srv_to_string(new_rp), result, (reply_flag==RS_REPLY));
  }
}

static void determine_survivors(int result, struct rproc *old_rp, struct rproc *new_rp,
                                struct rproc **surviving_rp, struct rproc **exiting_rp)
{
  *surviving_rp = (result == OK ? new_rp : old_rp);
  *exiting_rp = (result == OK ? old_rp : new_rp);
}

static void update_surviving_process(struct rproc *surviving_rp, struct rprocupd *rpupd)
{
  surviving_rp->r_flags &= ~RS_INITIALIZING;
  surviving_rp->r_check_tm = 0;
  surviving_rp->r_alive_tm = getticks();
  rpupd->rp = surviving_rp;
}

static void unlink_versions(struct rproc *old_rp, struct rproc *new_rp)
{
  old_rp->r_new_rp = NULL;
  new_rp->r_old_rp = NULL;
}

static void handle_surviving_process_reply(struct rproc *surviving_rp, int result, int reply_flag)
{
  surviving_rp->r_flags &= ~(RS_UPDATING|RS_PREPARE_DONE|RS_INIT_DONE|RS_INIT_PENDING);
  
  if(reply_flag == RS_REPLY) {
      send_reply_message(surviving_rp, result);
  }
  else if(reply_flag == RS_CANCEL) {
      handle_cancel_reply(surviving_rp);
  }
}

static void send_reply_message(struct rproc *surviving_rp, int result)
{
  message m;
  m.m_type = result;
  reply(surviving_rp->r_pub->endpoint, surviving_rp, &m);
}

static void handle_cancel_reply(struct rproc *surviving_rp)
{
  if(!(surviving_rp->r_flags & RS_TERMINATED)) {
      request_prepare_update_service(surviving_rp, SEF_LU_STATE_NULL);
  }
}

static void cleanup_exiting_version(struct rproc *exiting_rp, struct rprocupd *rpupd)
{
  struct rproc **rps;
  int nr_rps, i;

  get_service_instances(exiting_rp, &rps, &nr_rps);
  
  for(i = 0; i < nr_rps; i++) {
      cleanup_single_instance(rps[i], exiting_rp->r_old_rp, rpupd);
  }
}

static void cleanup_single_instance(struct rproc *rp, struct rproc *old_rp, struct rprocupd *rpupd)
{
  if(rp == old_rp && (rpupd->lu_flags & SEF_LU_DETACHED)) {
      cleanup_detached_instance(rp);
  }
  else {
      cleanup_service(rp);
  }
}

static void cleanup_detached_instance(struct rproc *rp)
{
  message m;
  m.m_type = EDEADEPT;
  rp->r_flags |= RS_CLEANUP_DETACH;
  cleanup_service(rp);
  reply(rp->r_pub->endpoint, rp, &m);
}

static void log_update_completed(struct rproc *surviving_rp, struct rprocupd *rpupd)
{
  if(rs_verbose) {
      printf("RS: %s ended the %s\n", srv_to_string(surviving_rp),
          srv_upd_to_string(rpupd));
  }
}

