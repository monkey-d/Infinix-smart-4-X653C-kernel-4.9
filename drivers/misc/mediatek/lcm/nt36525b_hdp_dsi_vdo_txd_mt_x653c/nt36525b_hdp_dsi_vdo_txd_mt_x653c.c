#ifndef BUILD_LK
#include <linux/string.h>
#include <linux/kernel.h>
#endif

#include "lcm_drv.h"

// ---------------------------------------------------------------------------
//  Local Constants
// ---------------------------------------------------------------------------

#define FRAME_WIDTH  (720)
#define FRAME_HEIGHT (1600)

#define REGFLAG_DELAY           0xFE
#define REGFLAG_END_OF_TABLE    0xFF

// ---------------------------------------------------------------------------
//  Local Variables
// ---------------------------------------------------------------------------
// Add this function before the LCM_DRIVER struct

static struct LCM_UTIL_FUNCS lcm_util = { 0 };

#define SET_RESET_PIN(v)    (lcm_util.set_reset_pin((v)))
#define MDELAY(n)           (lcm_util.mdelay(n))

// ---------------------------------------------------------------------------
//  Local Functions
// ---------------------------------------------------------------------------

#define dsi_set_cmdq_V2(cmd, count, ppara, force_update) \
    lcm_util.dsi_set_cmdq_V2(cmd, count, ppara, force_update)
#define dsi_write_cmd(cmd) \
    lcm_util.dsi_write_cmd(cmd)
#define dsi_write_regs(addr, pdata, byte_nums) \
    lcm_util.dsi_write_regs(addr, pdata, byte_nums)

struct LCM_setting_table {
    unsigned int cmd;
    unsigned char count;
    unsigned char para_list[64];
};

// ---------------------------------------------------------------------------
//  Init Data
// ---------------------------------------------------------------------------

static struct LCM_setting_table init_setting_vdo[] = {
    {0xFF, 1, {0x20}},
    {0xFB, 1, {0x01}},
    {0xB0, 16, {0x00,0x16,0x00,0x26,0x00,0x40,0x00,0x57,0x00,0x6B,0x00,0x7E,0x00,0x8E,0x00,0x9E}},
    {0xB1, 16, {0x00,0xAC,0x00,0xDE,0x01,0x03,0x01,0x3F,0x01,0x6B,0x01,0xB0,0x01,0xE8,0x01,0xEA}},
    {0xB2, 16, {0x02,0x1F,0x02,0x5C,0x02,0x86,0x02,0xBC,0x02,0xE8,0x03,0x15,0x03,0x28,0x03,0x39}},
    {0xB3, 12, {0x03,0x4C,0x03,0x64,0x03,0x76,0x03,0xA2,0x03,0xC8,0x03,0xE0}},
    {0xB4, 16, {0x00,0x16,0x00,0x26,0x00,0x40,0x00,0x57,0x00,0x6B,0x00,0x7E,0x00,0x8E,0x00,0x9E}},
    {0xB5, 16, {0x00,0xAC,0x00,0xDE,0x01,0x03,0x01,0x3F,0x01,0x6B,0x01,0xB0,0x01,0xE8,0x01,0xEA}},
    {0xB6, 16, {0x02,0x1F,0x02,0x5C,0x02,0x86,0x02,0xBC,0x02,0xE8,0x03,0x15,0x03,0x28,0x03,0x39}},
    {0xB7, 12, {0x03,0x4C,0x03,0x64,0x03,0x76,0x03,0xA2,0x03,0xC8,0x03,0xE0}},
    {0xB8, 16, {0x00,0x16,0x00,0x26,0x00,0x40,0x00,0x57,0x00,0x6B,0x00,0x7E,0x00,0x8E,0x00,0x9E}},
    {0xB9, 16, {0x00,0xAC,0x00,0xDE,0x01,0x03,0x01,0x3F,0x01,0x6B,0x01,0xB0,0x01,0xE8,0x01,0xEA}},
    {0xBA, 16, {0x02,0x1F,0x02,0x5C,0x02,0x86,0x02,0xBC,0x02,0xE8,0x03,0x15,0x03,0x28,0x03,0x39}},
    {0xBB, 12, {0x03,0x4C,0x03,0x64,0x03,0x76,0x03,0xA2,0x03,0xC8,0x03,0xE0}},
    {0xFF, 1, {0x21}},
    {0xFB, 1, {0x01}},
    {0x11, 0, {}},
    {REGFLAG_DELAY, 120, {}},
    {0x29, 0, {}},
    {REGFLAG_DELAY, 20, {}},
    {REGFLAG_END_OF_TABLE, 0x00, {}}
};

static struct LCM_setting_table lcm_suspend_setting[] = {
    {0x28, 0, {}},
    {REGFLAG_DELAY, 20, {}},
    {0x10, 0, {}},
    {REGFLAG_DELAY, 80, {}},
    {REGFLAG_END_OF_TABLE, 0x00, {}}
};

static void push_table(struct LCM_setting_table *table, unsigned int count, unsigned char force_update)
{
    unsigned int i;
    for (i = 0; i < count; i++) {
        unsigned int cmd = table[i].cmd;
        switch (cmd) {
            case REGFLAG_DELAY:
                MDELAY(table[i].count);
                break;
            case REGFLAG_END_OF_TABLE:
                break;
            default:
                dsi_set_cmdq_V2(cmd, table[i].count, table[i].para_list, force_update);
        }
    }
}

// ---------------------------------------------------------------------------
//  LCM Driver Implementations
// ---------------------------------------------------------------------------

static void lcm_set_util_funcs(const struct LCM_UTIL_FUNCS *util) {
    memcpy(&lcm_util, util, sizeof(struct LCM_UTIL_FUNCS));
}

static void lcm_get_params(struct LCM_PARAMS *params) {
    memset(params, 0, sizeof(struct LCM_PARAMS));
    params->type = LCM_TYPE_DSI;
    params->width = FRAME_WIDTH;
    params->height = FRAME_HEIGHT;
    
    // VIDEO MODE SETTINGS
    params->dsi.mode = SYNC_PULSE_VDO_MODE;
    params->dsi.LANE_NUM = LCM_THREE_LANE;
    params->dsi.data_format.format = LCM_DSI_FORMAT_RGB888;
    params->dsi.PS = LCM_PACKED_PS_24BIT_RGB888;
    
    // TIMING
    params->dsi.vertical_sync_active = 2;
    params->dsi.vertical_backporch = 254;
    params->dsi.vertical_frontporch = 10;
    params->dsi.vertical_active_line = FRAME_HEIGHT;
    params->dsi.horizontal_sync_active = 4;
    params->dsi.horizontal_backporch = 44;
    params->dsi.horizontal_frontporch = 8;
    params->dsi.horizontal_active_pixel = FRAME_WIDTH;
    params->dsi.PLL_CLOCK = 360;

    // --- SCRCPY / BLACK SCREEN FIXES ---
    // Force DSI clock to run continuously. 
    // This allows the encoder to grab frames even if the panel is idle.
    params->dsi.cont_clock = 1; 
    
    // --- PMIC / STABILITY FIXES ---
    // Ensure ESD checking is enabled in the parameters (even if callback is simple)
    params->dsi.esd_check_enable = 1;
    params->dsi.customization_esd_check_enable = 1;
    params->dsi.lcm_esd_check_table[0].cmd = 0x0A; // Read Power Mode
    params->dsi.lcm_esd_check_table[0].count = 1;
    params->dsi.lcm_esd_check_table[0].para_list[0] = 0x9C; // Expect 0x9C (Normal)
}


static void lcm_init(void) {
    SET_RESET_PIN(0);
    MDELAY(20);
    SET_RESET_PIN(1);
    MDELAY(20);
    push_table(init_setting_vdo, sizeof(init_setting_vdo) / sizeof(struct LCM_setting_table), 1);
}

static void lcm_suspend(void) {
    push_table(lcm_suspend_setting, sizeof(lcm_suspend_setting) / sizeof(struct LCM_setting_table), 1);
}

static void lcm_resume(void) {
    lcm_init();
}

// Add this function before the LCM_DRIVER struct
static unsigned int lcm_compare_id(void)
{
    return 1; 
}

struct LCM_DRIVER nt36525b_hdp_dsi_vdo_txd_mt_x653c_lcm_drv = {
    .name = "nt36525b_hdp_dsi_vdo_txd_mt_x653c",
    .set_util_funcs = lcm_set_util_funcs,
    .get_params = lcm_get_params,
    .init = lcm_init,
    .suspend = lcm_suspend,
    .resume = lcm_resume,
    .compare_id = lcm_compare_id,

};


