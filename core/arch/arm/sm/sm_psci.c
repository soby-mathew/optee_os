/*
 * Copyright (c) 2017, Linaro Limited
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <kernel/misc.h>
#include <kernel/generic_boot.h>
#include <platform_config.h>
#include <psci_optee_lib.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>
#include <string.h>
#include "sm_private.h"

#include <platform_config.h>

#define plat_my_core_pos()	get_core_pos()

/* Pointers to per-core cpu contexts */
static void *optee_psci_ctx_ptr[CFG_TEE_CORE_NB_CORE];

/*******************************************************************************
 * This function returns a pointer to the most recent 'cpu_context' structure
 * for the calling CPU that was set as the context for the specified security
 * state. NULL is returned if no such structure has been specified.
 ******************************************************************************/
void *cm_get_context(uint32_t security_state __maybe_unused)
{
	assert(security_state == NON_SECURE);
	return optee_psci_ctx_ptr[plat_my_core_pos()];
}

/*******************************************************************************
 * This function sets the pointer to the current 'cpu_context' structure for the
 * specified security state for the calling CPU
 ******************************************************************************/
void cm_set_context(void *context, uint32_t security_state __maybe_unused)
{
	assert(security_state == NON_SECURE);
	optee_psci_ctx_ptr[plat_my_core_pos()] = context;
}

/*******************************************************************************
 * This function returns a pointer to the most recent 'cpu_context' structure
 * for the CPU identified by `cpu_idx` that was set as the context for the
 * specified security state. NULL is returned if no such structure has been
 * specified.
 ******************************************************************************/
void *cm_get_context_by_index(unsigned int cpu_idx,
				unsigned int security_state __maybe_unused)
{
	assert(security_state == NON_SECURE);
	return optee_psci_ctx_ptr[cpu_idx];
}

/*******************************************************************************
 * This function sets the pointer to the current 'cpu_context' structure for the
 * specified security state for the CPU identified by CPU index.
 ******************************************************************************/
void cm_set_context_by_index(unsigned int cpu_idx, void *context,
				unsigned int security_state __maybe_unused)
{
	assert(security_state == NON_SECURE);
	optee_psci_ctx_ptr[cpu_idx] = context;
}


static void copy_psci_ctx_to_nctx(const regs_t *cpu_reg_ctx,
				struct sm_nsec_ctx* nctx)
{
	uint32_t sctlr, scr;

	nctx->r0 = read_ctx_reg(cpu_reg_ctx, CTX_GPREG_R0);
	nctx->mon_lr = read_ctx_reg(cpu_reg_ctx, CTX_LR);
	nctx->mon_spsr = read_ctx_reg(cpu_reg_ctx, CTX_SPSR);

	scr = read_scr();
	scr |= read_ctx_reg(cpu_reg_ctx, CTX_SCR);
	write_scr(scr);
	/*
	 * Make sure the write to SCR is complete so that
	 * we can access NS SCTLR
	 */
	isb();
	sctlr = read_ctx_reg(cpu_reg_ctx, CTX_NS_SCTLR);
	write_sctlr(sctlr);
	isb();

	write_scr(read_scr() & ~SCR_NS);
	isb();
}

void handle_entrydone_smc(uint32_t smc_fid, struct sm_nsec_ctx* nctx)
{
	void *psci_ctx = NULL;

	if (smc_fid != TEESMC_OPTEED_RETURN_ENTRY_DONE &&
			smc_fid != TEESMC_OPTEED_RETURN_WARM_BOOT_DONE)
		return;

	if (smc_fid == TEESMC_OPTEED_RETURN_ENTRY_DONE) {
		entry_point_info_t non_sec_ep_info;
		DEFINE_STATIC_PSCI_LIB_ARGS_V1(psci_args, optee_warm_reset_entrypoint);

		memset(&non_sec_ep_info, 0, sizeof(non_sec_ep_info));

		optee_platform_setup();

		SET_PARAM_HEAD(&non_sec_ep_info,
					PARAM_EP,
					VERSION_1,
					0);

#if !defined(CFG_NS_ENTRY_ADDR)
#error "Please define CFG_NS_ENTRY_ADDR"
#endif
		non_sec_ep_info.pc = (uintptr_t)CFG_NS_ENTRY_ADDR;
		non_sec_ep_info.spsr =	CPSR_MODE_HYP | CPSR_FIA;
		psci_setup(&psci_args);
		SET_SECURITY_STATE(non_sec_ep_info.h.attr, NON_SECURE);
		psci_prepare_next_non_secure_ctx(&non_sec_ep_info);
	} else
		psci_warmboot_entrypoint();

	psci_ctx = cm_get_context(NON_SECURE);
	assert(psci_ctx);

	/* Zero out the non secure context */
	memset(nctx, 0, sizeof(*nctx));

	/* Copy r0, lr and spsr from cpu context to SMC context */
	copy_psci_ctx_to_nctx(get_regs_ctx(psci_ctx), nctx);
}

void invoke_psci_handler(struct sm_ctx *ctx)
{
	uint32_t ret, cookie, handle, flags = SMC_FROM_NON_SECURE;
	ret = psci_smc_handler(ctx->nsec.r0, ctx->nsec.r1, ctx->nsec.r2,
			ctx->nsec.r3, ctx->nsec.r4, &cookie, &handle, flags);

	ctx->nsec.r0 = ret;
}
