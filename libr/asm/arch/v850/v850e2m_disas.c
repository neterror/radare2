
#include <r_types.h>
#include <r_util.h>
#include <r_endian.h>

#include "v850_disas.h"

typedef enum {
    INVALID,
    PREPARE_1,
    PREPARE_2,
    LD_BU_1,
    JARL_1
} Opcode;

typedef struct {
    const char* mnemonics;
    ut32 pattern;
    ut32 mask;
    Opcode opcode;
    bool reg2Not0; //the first 5 bits distinguish between different instructions, even if not part of the opcode
} Instruction;


static inline ut32 get_pattern(const ut8 *instr) {
    return (instr[1] << 24) | (instr[0] << 16) | (instr[3] << 8) | instr[2];
}

static const Instruction instructions[] = {
    {"prepare",   0x07800001, 0xFFC0001F,  PREPARE_1, false}, 
    {"prepare",   0x07800003, 0xFFC00007,  PREPARE_2, false},
    {"ld.bu",     0x07800001, 0x07C00001,  LD_BU_1,   true}, //if reg2 is 0, then the instruction is prepare
    {"jarl",      0x07800000, 0x07C00001,  JARL_1,    true}
};

//original BF FF 9C FF
// FF BF FF 9C


static int the_decode_jarl(const ut8 *instr, int len, struct v850_cmd *cmd) {
    ut32 code = get_pattern(instr);
    ut8 reg = (code >> 27) & 0x1F;
    ut32 disp22 = code & 0x003FFFFF;
    if (disp22 & 0x00400000) { //sign extension required
        disp22 |= 0xFFC00000;
    }
    printf("current address = %x, disp22 = %d\n", cmd->addr, disp22);
    ut32 addr = cmd->addr + disp22;
	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", "jarl");
	snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%08x, r%d",
              addr, reg);
    return 4;
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

static int decode_prepare(const ut8 *instr, int len, struct v850_cmd *cmd) {
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

    if ((word2 & 0x3) == 3) {
        //format2. todo
    } else {
        //format1
        ut8 imm5 = (word1 >> 1) & 0x1F;
        sprintf (cmd->instr, "%s", "prepare");
        snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "{%s},%d",
                  prepare_registers(word1, word2), imm5);
    }

	return 4;
}


static int decode_ldbu(const ut8 *instr, int len, struct v850_cmd *cmd) {
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

    ut8 reg2 = (word1 >> 11) & 0x1F;
    ut8 reg1 = word1 & 0x1F;
    ut8 b = (word1 >> 5) & 1;
    ut8 disp = (word2 & 0xFFFE) | b;

    snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", "ld.bu");
    snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "%d[r%u],r%u",  disp, reg1, reg2);
    return 4;
}


static Opcode find_opcode(const ut8 *instr) {
    static const size_t count = sizeof(instructions) / sizeof(instructions[0]);
    ut32 pattern = get_pattern(instr);
    Opcode result = INVALID;
    for (int i = 0; i < count; ++i) {
        if ((instructions[i].mask & pattern) == instructions[i].pattern) {
            //some instructions like LD.BU and PREPARE match on the opcode bits.
            //But the reg2 field (first 5 bits) should not be 0 on one of them
            bool mismatch = instructions[i].reg2Not0 && ((pattern & 0xF8000000) == 0);
            if (!mismatch) { 
                result = instructions[i].opcode;
                break;
            }
        }
    }
    return result;
}

static int decode(const ut8 *instr, int len, struct v850_cmd *cmd, Opcode opcode) {
    int ret = -1;
    switch(opcode) {
    case PREPARE_1:
        ret = decode_prepare (instr, len, cmd);
        break;
    case PREPARE_2:
        break;
    case LD_BU_1:
        ret = decode_ldbu(instr, len, cmd);
        break;
    case JARL_1:
        ret = the_decode_jarl(instr, len, cmd);
        break;
    default:
        break;
    }

    return ret;
}

int v850e2m_try_decode (const ut8 *instr, int len, struct v850_cmd *cmd) {
    int ret = -1;
    Opcode opcode = INVALID;
	if (len >= 4) {
        opcode = find_opcode(instr);
        if (opcode != INVALID) {
            ret = decode(instr, len, cmd, opcode);
        }
	}
    return ret;
}

