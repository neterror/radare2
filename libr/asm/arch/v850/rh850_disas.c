#include <r_types.h>
#include <r_util.h>
#include <r_endian.h>

#include "v850_disas.h"

typedef enum {
    INVALID,
    PREPARE_F1,
    PREPARE_F2,
    LD_B_F1,
    LD_BU_F1,
    JARL_F1,
    BCOND
} Opcode;

typedef struct {
    const char* mnemonics;
    ut32 pattern;
    ut32 mask;
    Opcode opcode;
    bool reg2Not0; //the first 5 bits distinguish between different instructions, even if not part of the opcode
} Instruction;


static const char *conds[] = {
	[V850_COND_V]	= "v",
	[V850_COND_CL]	= "cl",
	[V850_COND_ZE]	= "z",
	[V850_COND_NH]	= "nh",
	[V850_COND_N]	= "n",
	[V850_COND_AL]	= "",
	[V850_COND_LT]	= "lt",
	[V850_COND_LE]	= "le",
	[V850_COND_NV]	= "nv",
	[V850_COND_NC]	= "nc",
	[V850_COND_NZ]	= "nz",
	[V850_COND_H]	= "h",
	[V850_COND_NS]	= "ns",
	[V850_COND_SA]	= "sa",
	[V850_COND_GE]	= "ge",
	[V850_COND_GT]	= "gt",
};
    
static const Instruction instructions[] = {
    //mnemonic      pattern     mask
    {"jarl",      0x07800000, 0x07C00001,  JARL_F1,    true}, //if reg2 should not be 0
    {"prepare",   0x07800001, 0xFFC0001F,  PREPARE_F1, false}, 
    {"ld.b",      0x07000000, 0x07E00000,  LD_B_F1,    false},
    {"ld.bu",     0x07800001, 0x07C00001,  LD_BU_F1,   true}, //if reg2 should not be 0
    {NULL,        0x07E00001, 0x07E00001,  BCOND,      false}

};


static inline ut32 get_pattern(const ut8 *instr) {
    return (instr[1] << 24) | (instr[0] << 16) | (instr[3] << 8) | instr[2];
}

static const char* regname(ut8 reg) {
    static const char* names[] = {
        "r0", "r1", "r2", "sp", "gp", "tp", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
        "r15", "r19", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",
        "r28", "r29", "ep", "lp", "n/a"
    };

    if (reg > 32) {
        reg = 32;
    }
    return names[reg];
}

static const char* reg1(ut16 word1) {
    return regname(word1 & 0x1F);
}
static const char* reg2(ut16 word1) {
    return regname((word1 >> 11) & 0x1F);
}

static int find_opcode(const ut8 *instr) {
    static const size_t count = sizeof(instructions) / sizeof(instructions[0]);
    ut32 pattern = get_pattern(instr);
    int result = -1;
    for (int i = 0; i < count; ++i) {
        if ((instructions[i].mask & pattern) == instructions[i].pattern) {
            //some instructions like LD.BU and PREPARE match on the opcode bits.
            //But the reg2 field (first 5 bits) should not be 0 on one of them
            bool mismatch = instructions[i].reg2Not0 && ((pattern & 0xF8000000) == 0);
            if (!mismatch) { 
                result = i;
                break;
            }
        }
    }
    return result;
}



static char* prepare_registers(ut16 word1, ut16 word2) {
    static char buf[V850_INSTR_MAXLEN];
    //from page 131 from V850E2M
    static const char* list12[] = {"r30", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                   "lr", "r29", "r28", "r23", "r22", "r21", "r20", "r27", "r26", "r25", "r24"};
    char* p = buf;
    ut16 mask = 0x20;
    buf[0] = 0;
    for (ut8 idx = 21; idx < 32; ++idx) {
        if (word2 & mask) {
            int len = strlen(list12[idx]);
            if (p == buf) {
                sprintf(p, "%s", list12[idx]);
            } else {
                sprintf(p, ",%s", list12[idx]);
                p+=1;
            }
            p+=len;
        }
        mask <<= 1;
    }
    if (word1 & 1) {
        if (p == buf) {
            sprintf(p, "%s", list12[0]);
        } else {
            sprintf(p, ",%s", list12[0]);
        }
    }
    return buf;
}


static int decode_jarl_f1(const ut8 *instr, int len, struct v850_cmd *cmd) {
    ut32 code = get_pattern(instr);
    ut8 reg1 = (code >> 27) & 0x1F;
    ut32 disp22 = code & 0x003FFFFF;
    if (disp22 & 0x00200000) { //sign extension required
        disp22 |= 0xFFC00000;
    }
    ut32 addr = cmd->addr + disp22;
	snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%08x, r%d",
              addr, reg1);
    return 4;
}


static int decode_prepare_f1(const ut8 *instr, int len, struct v850_cmd *cmd) {
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);
    ut8 imm5 = (word1 >> 1) & 0x1F;
    snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "{%s},%d",
              prepare_registers(word1, word2), imm5);
	return 4;
}

static int decode_ldb_f1(const ut8 *instr, int len, struct v850_cmd *cmd) {
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

    ut16 disp16 = word2;

    snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x[%s],%s",  disp16, reg1(word1), reg2(word1));
    return 4;
}

static int decode_ldbu_f1(const ut8 *instr, int len, struct v850_cmd *cmd) {
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

    ut8 b = (word1 >> 5) & 1;
    ut8 disp = (word2 & 0xFFFE) | b;

    snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "%d[%s],%s",  disp, reg1(word1), reg2(word1));
    return 4;
}

static int decode_bcond_f1(const ut8 *instr, int len, struct v850_cmd *cmd) {
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

    ut8 condition = word1 & 0xF;
    snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "b%s", conds[condition]);
    ut32 disp = word2 & 0xFFFE;
    ut32 msb = (word1 >> 4) & 1;
    if (msb) {
        disp |= 0xFFFF0000;
    }
    snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x",  cmd->addr + disp);
    return 4;
}


static int decode(const ut8 *instr, int len, struct v850_cmd *cmd, Opcode opcode) {
    int ret = -1;
    switch(opcode) {
    case PREPARE_F1:
        ret = decode_prepare_f1 (instr, len, cmd);
        break;
    case PREPARE_F2:
        break;
    case LD_BU_F1:
        ret = decode_ldbu_f1(instr, len, cmd);
        break;
    case LD_B_F1:
        ret = decode_ldb_f1(instr, len, cmd);
        break;
    case JARL_F1:
        ret = decode_jarl_f1(instr, len, cmd);
        break;
    case BCOND:
        ret = decode_bcond_f1(instr, len, cmd);
        break;
    default:
        break;
    }

    return ret;
}

int rh850_try_decode (const ut8 *instr, int len, struct v850_cmd *cmd) {
    int ret = -1;
    Opcode opcode = INVALID;
	if (len >= 4) {
        int idx = find_opcode(instr); 
        if (idx != -1) {
            opcode = instructions[idx].opcode;
            ret = decode(instr, len, cmd, opcode);
            if ((ret != -1) && instructions[idx].mnemonics) {
                snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", instructions[idx].mnemonics);
            }
        }
	}
    return ret;
}

