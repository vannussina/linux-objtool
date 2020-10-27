// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#include <stdlib.h>
#include <string.h>

#include <linux/objtool.h>
#include <asm/orc_types.h>

#include "check.h"
#include "warn.h"

int create_orc(struct objtool_file *file)
{
	struct instruction *insn;

	for_each_insn(file, insn) {
		struct orc_entry *orc = &insn->orc;
		struct cfi_reg *cfa = &insn->cfi.cfa;
		struct cfi_reg *bp = &insn->cfi.regs[CFI_BP];

		if (!insn->sec->text)
			continue;

		orc->end = insn->cfi.end;

		if (cfa->base == CFI_UNDEFINED) {
			orc->sp_reg = ORC_REG_UNDEFINED;
			continue;
		}

		switch (cfa->base) {
		case CFI_SP:
			orc->sp_reg = ORC_REG_SP;
			break;
		case CFI_SP_INDIRECT:
			orc->sp_reg = ORC_REG_SP_INDIRECT;
			break;
		case CFI_BP:
			orc->sp_reg = ORC_REG_BP;
			break;
		case CFI_BP_INDIRECT:
			orc->sp_reg = ORC_REG_BP_INDIRECT;
			break;
		case CFI_R10:
			orc->sp_reg = ORC_REG_R10;
			break;
		case CFI_R13:
			orc->sp_reg = ORC_REG_R13;
			break;
		case CFI_DI:
			orc->sp_reg = ORC_REG_DI;
			break;
		case CFI_DX:
			orc->sp_reg = ORC_REG_DX;
			break;
		default:
			WARN_FUNC("unknown CFA base reg %d",
				  insn->sec, insn->offset, cfa->base);
			return -1;
		}

		switch(bp->base) {
		case CFI_UNDEFINED:
			orc->bp_reg = ORC_REG_UNDEFINED;
			break;
		case CFI_CFA:
			orc->bp_reg = ORC_REG_PREV_SP;
			break;
		case CFI_BP:
			orc->bp_reg = ORC_REG_BP;
			break;
		default:
			WARN_FUNC("unknown BP base reg %d",
				  insn->sec, insn->offset, bp->base);
			return -1;
		}

		orc->sp_offset = cfa->offset;
		orc->bp_offset = bp->offset;
		orc->type = insn->cfi.type;
	}

	return 0;
}

static int create_orc_entry(struct elf *elf, struct section *u_sec, struct section *ip_relocsec,
				unsigned int idx, struct section *insn_sec,
				unsigned long insn_off, struct orc_entry *o)
{
	struct orc_entry *orc;
	struct reloc *reloc;

	/* populate ORC data */
	orc = (struct orc_entry *)u_sec->data->d_buf + idx;
	memcpy(orc, o, sizeof(*orc));

	/* populate reloc for ip */
	reloc = malloc(sizeof(*reloc));
	if (!reloc) {
		perror("malloc");
		return -1;
	}
	memset(reloc, 0, sizeof(*reloc));

	if (insn_sec->sym) {
		reloc->sym = insn_sec->sym;
		reloc->addend = insn_off;
	} else {
		/*
		 * The Clang assembler doesn't produce section symbols, so we
		 * have to reference the function symbol instead:
		 */
		reloc->sym = find_symbol_containing(insn_sec, insn_off);
		if (!reloc->sym) {
			/*
			 * Hack alert.  This happens when we need to reference
			 * the NOP pad insn immediately after the function.
			 */
			reloc->sym = find_symbol_containing(insn_sec,
							   insn_off - 1);
		}
		if (!reloc->sym) {
			WARN("missing symbol for insn at offset 0x%lx\n",
			     insn_off);
			return -1;
		}

		reloc->addend = insn_off - reloc->sym->offset;
	}

	reloc->type = R_X86_64_PC32;
	reloc->offset = idx * sizeof(int);
	reloc->sec = ip_relocsec;

	elf_add_reloc(elf, reloc);

	return 0;
}

static unsigned orc_entry_count(struct objtool_file *file, struct section *sec)
{
	struct instruction *insn, *prev;
	unsigned count = 0;

	prev = NULL;
	sec_for_each_insn(file, sec, insn) {
		if (!prev || memcmp(&insn->orc, &prev->orc,
				    sizeof(struct orc_entry)))
			count++;
		prev = insn;
	}
	if (prev)
		count++;
	return count;
}

int create_orc_sections(struct objtool_file *file)
{
	struct instruction *insn, *prev_insn;
	struct section *sec, *u_sec, *ip_relocsec;
	unsigned int idx;

	struct orc_entry empty = {
		.sp_reg = ORC_REG_UNDEFINED,
		.bp_reg  = ORC_REG_UNDEFINED,
		.type    = UNWIND_HINT_TYPE_CALL,
	};

	sec = find_section_by_name(file->elf, ".orc_unwind");
	if (sec) {
		WARN("file already has .orc_unwind section, skipping");
		return -1;
	}

	/* count the number of needed orcs */
	idx = 0;
	for_each_sec(file, sec) {
		if (!sec->text)
			continue;
		if (sec->sh.sh_flags & SHF_GROUP)
			continue;
		idx += orc_entry_count(file, sec);
	}

	/* create .orc_unwind_ip and .rela.orc_unwind_ip sections */
	sec = elf_create_section(file->elf, ".orc_unwind_ip", 0, sizeof(int), idx);
	if (!sec)
		return -1;

	ip_relocsec = elf_create_reloc_section(file->elf, sec, SHT_RELA);
	if (!ip_relocsec)
		return -1;

	/* create .orc_unwind section */
	u_sec = elf_create_section(file->elf, ".orc_unwind", 0,
				   sizeof(struct orc_entry), idx);

	/* populate sections */
	idx = 0;
	for_each_sec(file, sec) {
		struct section *reloc;
		struct section *unwind;
		unsigned counter;
		if (!sec->text)
			continue;
		if (sec->sh.sh_flags & SHF_GROUP) {
			struct section *i_sec, *group;
			char name[strlen(".orc_unwind_ip") + strlen(sec->name) + 1];

			counter = orc_entry_count(file, sec);
			if (counter == 0)
				continue;

			snprintf(name, sizeof(name), ".orc_unwind_ip%s", sec->name);
			/* create .orc_unwind_ip and .rela.orc_unwind_ip sections */
			i_sec = elf_create_section(file->elf, name, SHF_GROUP, sizeof(int), counter);
			if (!i_sec)
				return -1;

			reloc = elf_create_reloc_section(file->elf, i_sec, SHT_RELA);
			if (!reloc)
				return -1;

			/* create .orc_unwind section */
			snprintf(name, sizeof(name), ".orc_unwind%s", sec->name);
			unwind= elf_create_section(file->elf, name, SHF_GROUP,
						   sizeof(struct orc_entry), counter);

			/* add to groups */
			for_each_sec(file, group) {
				bool relevant = false;
				unsigned i;
				Elf32_Word *member;
				if (group->sh.sh_type != SHT_GROUP)
					continue;

				member = group->data->d_buf;
				for (i = 1; !relevant && i < group->len / sizeof(*member); ++i)
					if (sec->idx == member[i])
						relevant = true;
				if (!relevant)
					continue;
				WARN("group: %s len:%u size:%zu", group->name,
				     group->len, group->data->d_size);

				member = malloc(group->len + (sizeof(*member) * 3));
				if (!member)
					return -1;
				memcpy(member, group->data->d_buf, group->len);
				member[group->len/sizeof(*member) + 0] = unwind->idx;
				member[group->len/sizeof(*member) + 1] = i_sec->idx;
				member[group->len/sizeof(*member) + 2] = reloc->idx;
				group->data->d_buf = member;
				group->data->d_size = group->len + (3 * sizeof(*member));
				group->len = group->len + (3 * sizeof(*member));

				group->changed = true;
			}

			counter = 0;
		} else {
			unwind = u_sec;
			reloc = ip_relocsec;
			counter = idx;
		}
		WARN("create orc in %s", unwind->name);

		prev_insn = NULL;
		sec_for_each_insn(file, sec, insn) {
			if (!prev_insn || memcmp(&insn->orc, &prev_insn->orc,
						 sizeof(struct orc_entry))) {

				if (create_orc_entry(file->elf, unwind, reloc,
						     counter, insn->sec,
						     insn->offset, &insn->orc))
					return -1;

				counter++;
			}
			prev_insn = insn;
		}

		/* section terminator */
		if (prev_insn) {
			if (create_orc_entry(file->elf, unwind, reloc, counter,
					     prev_insn->sec,
					     prev_insn->offset + prev_insn->len,
					     &empty))
				return -1;

			counter++;
		}

		if (!(sec->sh.sh_flags & SHF_GROUP))
			idx = counter;
		else if (elf_rebuild_reloc_section(file->elf, reloc))
			return -1;
	}

	if (elf_rebuild_reloc_section(file->elf, ip_relocsec))
		return -1;

	return 0;
}
