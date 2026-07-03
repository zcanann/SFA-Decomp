#include "main/audio/inp_ctrl.h"
#include "main/audio/synth_scale.h"
extern u32 sndRandSeed;
s16 sndSintab[1036] = {
    0, 6, 12, 18, 25, 31, 37, 43, 50, 56, 62, 69, 75, 81, 87, 94,
    100, 106, 113, 119, 125, 131, 138, 144, 150, 157, 163, 169, 175, 182, 188, 194,
    200, 207, 213, 219, 226, 232, 238, 244, 251, 257, 263, 269, 276, 282, 288, 295,
    301, 307, 313, 320, 326, 332, 338, 345, 351, 357, 363, 370, 376, 382, 388, 395,
    401, 407, 413, 420, 426, 432, 438, 445, 451, 457, 463, 470, 476, 482, 488, 495,
    501, 507, 513, 520, 526, 532, 538, 545, 551, 557, 563, 569, 576, 582, 588, 594,
    601, 607, 613, 619, 625, 632, 638, 644, 650, 656, 663, 669, 675, 681, 687, 694,
    700, 706, 712, 718, 725, 731, 737, 743, 749, 755, 762, 768, 774, 780, 786, 792,
    799, 805, 811, 817, 823, 829, 836, 842, 848, 854, 860, 866, 872, 879, 885, 891,
    897, 903, 909, 915, 921, 928, 934, 940, 946, 952, 958, 964, 970, 976, 983, 989,
    995, 1001, 1007, 1013, 1019, 1025, 1031, 1037, 1043, 1050, 1056, 1062, 1068, 1074, 1080, 1086,
    1092, 1098, 1104, 1110, 1116, 1122, 1128, 1134, 1140, 1146, 1152, 1158, 1164, 1170, 1176, 1182,
    1189, 1195, 1201, 1207, 1213, 1219, 1225, 1231, 1237, 1243, 1248, 1254, 1260, 1266, 1272, 1278,
    1284, 1290, 1296, 1302, 1308, 1314, 1320, 1326, 1332, 1338, 1344, 1350, 1356, 1362, 1368, 1373,
    1379, 1385, 1391, 1397, 1403, 1409, 1415, 1421, 1427, 1433, 1438, 1444, 1450, 1456, 1462, 1468,
    1474, 1479, 1485, 1491, 1497, 1503, 1509, 1515, 1520, 1526, 1532, 1538, 1544, 1550, 1555, 1561,
    1567, 1573, 1579, 1584, 1590, 1596, 1602, 1608, 1613, 1619, 1625, 1631, 1636, 1642, 1648, 1654,
    1659, 1665, 1671, 1677, 1682, 1688, 1694, 1699, 1705, 1711, 1717, 1722, 1728, 1734, 1739, 1745,
    1751, 1756, 1762, 1768, 1773, 1779, 1785, 1790, 1796, 1802, 1807, 1813, 1819, 1824, 1830, 1835,
    1841, 1847, 1852, 1858, 1864, 1869, 1875, 1880, 1886, 1891, 1897, 1903, 1908, 1914, 1919, 1925,
    1930, 1936, 1941, 1947, 1952, 1958, 1964, 1969, 1975, 1980, 1986, 1991, 1997, 2002, 2007, 2013,
    2018, 2024, 2029, 2035, 2040, 2046, 2051, 2057, 2062, 2067, 2073, 2078, 2084, 2089, 2094, 2100,
    2105, 2111, 2116, 2121, 2127, 2132, 2138, 2143, 2148, 2154, 2159, 2164, 2170, 2175, 2180, 2186,
    2191, 2196, 2201, 2207, 2212, 2217, 2223, 2228, 2233, 2238, 2244, 2249, 2254, 2259, 2265, 2270,
    2275, 2280, 2286, 2291, 2296, 2301, 2306, 2312, 2317, 2322, 2327, 2332, 2337, 2343, 2348, 2353,
    2358, 2363, 2368, 2373, 2379, 2384, 2389, 2394, 2399, 2404, 2409, 2414, 2419, 2424, 2429, 2434,
    2439, 2445, 2450, 2455, 2460, 2465, 2470, 2475, 2480, 2485, 2490, 2495, 2500, 2505, 2510, 2515,
    2519, 2524, 2529, 2534, 2539, 2544, 2549, 2554, 2559, 2564, 2569, 2574, 2578, 2583, 2588, 2593,
    2598, 2603, 2608, 2613, 2617, 2622, 2627, 2632, 2637, 2641, 2646, 2651, 2656, 2661, 2665, 2670,
    2675, 2680, 2684, 2689, 2694, 2699, 2703, 2708, 2713, 2717, 2722, 2727, 2732, 2736, 2741, 2746,
    2750, 2755, 2760, 2764, 2769, 2773, 2778, 2783, 2787, 2792, 2796, 2801, 2806, 2810, 2815, 2819,
    2824, 2828, 2833, 2837, 2842, 2847, 2851, 2856, 2860, 2865, 2869, 2874, 2878, 2882, 2887, 2891,
    2896, 2900, 2905, 2909, 2914, 2918, 2922, 2927, 2931, 2936, 2940, 2944, 2949, 2953, 2957, 2962,
    2966, 2970, 2975, 2979, 2983, 2988, 2992, 2996, 3000, 3005, 3009, 3013, 3018, 3022, 3026, 3030,
    3034, 3039, 3043, 3047, 3051, 3055, 3060, 3064, 3068, 3072, 3076, 3080, 3085, 3089, 3093, 3097,
    3101, 3105, 3109, 3113, 3117, 3121, 3126, 3130, 3134, 3138, 3142, 3146, 3150, 3154, 3158, 3162,
    3166, 3170, 3174, 3178, 3182, 3186, 3190, 3193, 3197, 3201, 3205, 3209, 3213, 3217, 3221, 3225,
    3229, 3232, 3236, 3240, 3244, 3248, 3252, 3255, 3259, 3263, 3267, 3271, 3274, 3278, 3282, 3286,
    3289, 3293, 3297, 3301, 3304, 3308, 3312, 3315, 3319, 3323, 3326, 3330, 3334, 3337, 3341, 3345,
    3348, 3352, 3356, 3359, 3363, 3366, 3370, 3373, 3377, 3381, 3384, 3388, 3391, 3395, 3398, 3402,
    3405, 3409, 3412, 3416, 3419, 3423, 3426, 3429, 3433, 3436, 3440, 3443, 3447, 3450, 3453, 3457,
    3460, 3463, 3467, 3470, 3473, 3477, 3480, 3483, 3487, 3490, 3493, 3497, 3500, 3503, 3506, 3510,
    3513, 3516, 3519, 3522, 3526, 3529, 3532, 3535, 3538, 3541, 3545, 3548, 3551, 3554, 3557, 3560,
    3563, 3566, 3570, 3573, 3576, 3579, 3582, 3585, 3588, 3591, 3594, 3597, 3600, 3603, 3606, 3609,
    3612, 3615, 3618, 3621, 3624, 3627, 3629, 3632, 3635, 3638, 3641, 3644, 3647, 3650, 3652, 3655,
    3658, 3661, 3664, 3667, 3669, 3672, 3675, 3678, 3680, 3683, 3686, 3689, 3691, 3694, 3697, 3700,
    3702, 3705, 3708, 3710, 3713, 3716, 3718, 3721, 3723, 3726, 3729, 3731, 3734, 3736, 3739, 3742,
    3744, 3747, 3749, 3752, 3754, 3757, 3759, 3762, 3764, 3767, 3769, 3772, 3774, 3776, 3779, 3781,
    3784, 3786, 3789, 3791, 3793, 3796, 3798, 3800, 3803, 3805, 3807, 3810, 3812, 3814, 3816, 3819,
    3821, 3823, 3826, 3828, 3830, 3832, 3834, 3837, 3839, 3841, 3843, 3845, 3848, 3850, 3852, 3854,
    3856, 3858, 3860, 3862, 3864, 3867, 3869, 3871, 3873, 3875, 3877, 3879, 3881, 3883, 3885, 3887,
    3889, 3891, 3893, 3895, 3897, 3899, 3900, 3902, 3904, 3906, 3908, 3910, 3912, 3914, 3915, 3917,
    3919, 3921, 3923, 3925, 3926, 3928, 3930, 3932, 3933, 3935, 3937, 3939, 3940, 3942, 3944, 3945,
    3947, 3949, 3950, 3952, 3954, 3955, 3957, 3959, 3960, 3962, 3963, 3965, 3967, 3968, 3970, 3971,
    3973, 3974, 3976, 3977, 3979, 3980, 3982, 3983, 3985, 3986, 3988, 3989, 3990, 3992, 3993, 3995,
    3996, 3997, 3999, 4000, 4001, 4003, 4004, 4005, 4007, 4008, 4009, 4011, 4012, 4013, 4014, 4016,
    4017, 4018, 4019, 4020, 4022, 4023, 4024, 4025, 4026, 4027, 4029, 4030, 4031, 4032, 4033, 4034,
    4035, 4036, 4037, 4038, 4039, 4040, 4041, 4042, 4043, 4044, 4045, 4046, 4047, 4048, 4049, 4050,
    4051, 4052, 4053, 4054, 4055, 4056, 4057, 4057, 4058, 4059, 4060, 4061, 4062, 4062, 4063, 4064,
    4065, 4065, 4066, 4067, 4068, 4068, 4069, 4070, 4071, 4071, 4072, 4073, 4073, 4074, 4075, 4075,
    4076, 4076, 4077, 4078, 4078, 4079, 4079, 4080, 4080, 4081, 4081, 4082, 4082, 4083, 4083, 4084,
    4084, 4085, 4085, 4086, 4086, 4087, 4087, 4087, 4088, 4088, 4089, 4089, 4089, 4090, 4090, 4090,
    4091, 4091, 4091, 4091, 4092, 4092, 4092, 4092, 4093, 4093, 4093, 4093, 4094, 4094, 4094, 4094,
    4094, 4094, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * Bit-11 (0x800) accessor - slot at +0x3a4, cached u16 at +0x3c4.
 *
 * EN v1.1 Address: 0x802827C8, size 72b
 */
extern u8 lbl_803BDA74[];
extern u8 lbl_803BDEF4[];
extern u32 lbl_803D3CA0[];
extern u32 lbl_8032FFE0[];
extern u32 lbl_8032FFF0[];

u16 inpGetPostAuxB(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_POST_AUX_B) == 0)
    {
        return state->postAuxBInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_POST_AUX_B;
    return _GetInputValue(state, &state->postAuxBInput, state->midiSlot, state->midiEvent);
}

/*
 * Bit-12 (0x1000) accessor - slot at +0x3c8, cached u16 at +0x3e8.
 *
 * EN v1.1 Address: 0x80282810, size 72b
 */
u16 inpGetTremolo(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_TREMOLO) == 0)
    {
        return state->tremoloInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_TREMOLO;
    return _GetInputValue(state, &state->tremoloInput, state->midiSlot, state->midiEvent);
}

/*
 * Cached aux A input getter for a studio/channel/slot.
 */
u16 inpGetAuxA(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex)
{
    u32 flags;
    u32 mask;
    u32 maskedFlags;
    u32 isDirty;
    u32* dirtyWord;

    mask = lbl_8032FFE0[channel & 0xff];
    dirtyWord = (u32*)((u8*)lbl_803D3CA0 + ((handleIndex & 0xff) << 6) + ((auxIndex & 0xff) << 2));
    flags = *dirtyWord;
    maskedFlags = flags & mask;
    isDirty = !!maskedFlags;
    if (isDirty != 0)
    {
        *dirtyWord = flags & ~mask;
    }
    if (isDirty == 0)
    {
        return *(u16*)(lbl_803BDEF4 + (studio & 0xff) * 0x90 + (channel & 0xff) * 0x24 + 0x20);
    }
    return _GetInputValue(0,
                          (McmdInputSlot*)(lbl_803BDEF4 + (studio & 0xff) * 0x90 +
                              (channel & 0xff) * 0x24),
                          auxIndex, handleIndex);
}

/*
 * Cached aux B input getter for a studio/channel/slot.
 */
u16 inpGetAuxB(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex)
{
    u32 flags;
    u32 mask;
    u32 maskedFlags;
    u32 isDirty;
    u32* dirtyWord;

    mask = lbl_8032FFF0[channel & 0xff];
    dirtyWord = (u32*)((u8*)lbl_803D3CA0 + ((handleIndex & 0xff) << 6) + ((auxIndex & 0xff) << 2));
    flags = *dirtyWord;
    maskedFlags = flags & mask;
    isDirty = !!maskedFlags;
    if (isDirty != 0)
    {
        *dirtyWord = flags & ~mask;
    }
    if (isDirty == 0)
    {
        return *(u16*)(lbl_803BDA74 + (studio & 0xff) * 0x90 + (channel & 0xff) * 0x24 + 0x20);
    }
    return _GetInputValue(0,
                          (McmdInputSlot*)(lbl_803BDA74 + (studio & 0xff) * 0x90 +
                              (channel & 0xff) * 0x24),
                          auxIndex, handleIndex);
}

/*
 * inpInit - input/controller state init.
 *
 * EN v1.0 Address: 0x802829D0
 * EN v1.0 Size: 740b (0x2E4)
 */
void inpInit(u32 state)
{
    McmdVoiceState* vs = (McmdVoiceState*)state;

    if (state != 0)
    {
        vs->volumeInput.entries[0].controller = MCMD_CTRL_VOLUME;
        vs->volumeInput.entries[0].combineModeFlags = 0;
        vs->volumeInput.entries[0].scale = 0x10000;
        vs->volumeInput.entries[1].controller = MCMD_CTRL_EXPRESSION;
        vs->volumeInput.entries[1].combineModeFlags = 2;
        vs->volumeInput.entries[1].scale = 0x10000;
        vs->volumeInput.entryCount = 2;
        vs->panningInput.entries[0].controller = MCMD_CTRL_PANNING;
        vs->panningInput.entries[0].combineModeFlags = 0;
        vs->panningInput.entries[0].scale = 0x10000;
        vs->panningInput.entryCount = 1;
        vs->surPanningInput.entries[0].controller = MCMD_CTRL_SUR_PANNING;
        vs->surPanningInput.entries[0].combineModeFlags = 0;
        vs->surPanningInput.entries[0].scale = 0x10000;
        vs->surPanningInput.entryCount = 1;
        vs->pitchBendInput.entries[0].controller = MCMD_CTRL_PITCH_BEND;
        vs->pitchBendInput.entries[0].combineModeFlags = 0;
        vs->pitchBendInput.entries[0].scale = 0x10000;
        vs->pitchBendInput.entryCount = 1;
        vs->modulationInput.entries[0].controller = MCMD_CTRL_MODULATION;
        vs->modulationInput.entries[0].combineModeFlags = 0;
        vs->modulationInput.entries[0].scale = 0x10000;
        vs->modulationInput.entryCount = 1;
        vs->pedalInput.entries[0].controller = MCMD_CTRL_PEDAL;
        vs->pedalInput.entries[0].combineModeFlags = 0;
        vs->pedalInput.entries[0].scale = 0x10000;
        vs->pedalInput.entryCount = 1;
        vs->portamentoInput.entries[0].controller = MCMD_CTRL_PORTAMENTO;
        vs->portamentoInput.entries[0].combineModeFlags = 0;
        vs->portamentoInput.entries[0].scale = 0x10000;
        vs->portamentoInput.entryCount = 1;
        vs->preAuxAInput.entryCount = 0;
        vs->reverbInput.entries[0].controller = MCMD_CTRL_REVERB;
        vs->reverbInput.entries[0].combineModeFlags = 0;
        vs->reverbInput.entries[0].scale = 0x10000;
        vs->reverbInput.entryCount = 1;
        vs->preAuxBInput.entryCount = 0;
        vs->postAuxBInput.entries[0].controller = MCMD_CTRL_POST_AUX_B;
        vs->postAuxBInput.entries[0].combineModeFlags = 0;
        vs->postAuxBInput.entries[0].scale = 0x10000;
        vs->postAuxBInput.entryCount = 1;
        vs->dopplerInput.entries[0].controller = MCMD_CTRL_DOPPLER;
        vs->dopplerInput.entries[0].combineModeFlags = 0;
        vs->dopplerInput.entries[0].scale = 0x10000;
        vs->dopplerInput.entryCount = 1;
        vs->tremoloInput.entryCount = 0;
        vs->inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
        vs->exCtrlDirty[0] = 0;
        vs->exCtrlDirty[1] = 0;
        vs->unkA8[0] = 0;
    }
    else
    {
        int i;
        u8* b = lbl_803BDA74;
        u8* a = lbl_803BDEF4;
        u32* p = lbl_803D3CA0;

        a[0x22] = 0;
        b[0x22] = 0;
        a[0x46] = 0;
        b[0x46] = 0;
        a[0x6a] = 0;
        b[0x6a] = 0;
        a[0x8e] = 0;
        b[0x8e] = 0;
        a[0xb2] = 0;
        b[0xb2] = 0;
        a[0xd6] = 0;
        b[0xd6] = 0;
        a[0xfa] = 0;
        b[0xfa] = 0;
        a[0x11e] = 0;
        b[0x11e] = 0;
        a[0x142] = 0;
        b[0x142] = 0;
        a[0x166] = 0;
        b[0x166] = 0;
        a[0x18a] = 0;
        b[0x18a] = 0;
        a[0x1ae] = 0;
        b[0x1ae] = 0;
        a[0x1d2] = 0;
        b[0x1d2] = 0;
        a[0x1f6] = 0;
        b[0x1f6] = 0;
        a[0x21a] = 0;
        b[0x21a] = 0;
        a[0x23e] = 0;
        b[0x23e] = 0;
        a[0x262] = 0;
        b[0x262] = 0;
        a[0x286] = 0;
        b[0x286] = 0;
        a[0x2aa] = 0;
        b[0x2aa] = 0;
        a[0x2ce] = 0;
        b[0x2ce] = 0;
        a[0x2f2] = 0;
        b[0x2f2] = 0;
        a[0x316] = 0;
        b[0x316] = 0;
        a[0x33a] = 0;
        b[0x33a] = 0;
        a[0x35e] = 0;
        b[0x35e] = 0;
        a[0x382] = 0;
        b[0x382] = 0;
        a[0x3a6] = 0;
        b[0x3a6] = 0;
        a[0x3ca] = 0;
        b[0x3ca] = 0;
        a[0x3ee] = 0;
        b[0x3ee] = 0;
        a[0x412] = 0;
        b[0x412] = 0;
        a[0x436] = 0;
        b[0x436] = 0;
        a[0x45a] = 0;
        b[0x45a] = 0;
        a[0x47e] = 0;
        b[0x47e] = 0;

        for (i = 0; i < 8; i++)
        {
            u32* row = p + i * 16;
            row[0] = 0xff;
            row[1] = 0xff;
            row[2] = 0xff;
            row[3] = 0xff;
            row[4] = 0xff;
            row[5] = 0xff;
            row[6] = 0xff;
            row[7] = 0xff;
            row[8] = 0xff;
            row[9] = 0xff;
            row[10] = 0xff;
            row[11] = 0xff;
            row[12] = 0xff;
            row[13] = 0xff;
            row[14] = 0xff;
            row[15] = 0xff;
        }
    }
}

/*
 * Map an input byte (0x80..0x88) to a packed table value via a
 * jumptable, falling through for inputs outside that range.
 *
 * EN v1.1 Address: 0x80282CB4, size 112b
 */
#pragma dont_inline on
u32 inpTranslateExCtrl(u32 input)
{
    u32 value = input & 0xff;
    u32 idx = value - 0x80;
    switch (idx)
    {
    case 0: return MCMD_CTRL_PITCH_BEND;
    case 1: return 0x82;
    case 2: return MCMD_CTRL_EX_A0;
    case 3: return MCMD_CTRL_EX_A1;
    case 4: return MCMD_CTRL_SUR_PANNING;
    case 5: return MCMD_CTRL_DOPPLER;
    case 6: return MCMD_CTRL_MIDI_LAYER;
    case 7: return MCMD_CTRL_VOICE_AGE;
    case 8: return 0xa4;
    default: return input;
    }
}
#pragma dont_inline reset

/*
 * Read an extended controller value, with local state-backed overrides for
 * translated controller 0xA0/0xA1.
 */
u32 inpGetExCtrl(McmdVoiceState* state, u32 ctrl)
{
    int translated;
    u16 value;

    translated = inpTranslateExCtrl(ctrl) & 0xff;
    switch (translated)
    {
    case MCMD_CTRL_EX_A0:
        return state->exCtrlA0Value * 2 + 0x2000;
    case MCMD_CTRL_EX_A1:
        return state->exCtrlA1Value * 2 + 0x2000;
    default:
        if (state->midiSlot != 0xff)
        {
            extern u32 inpGetMidiCtrl(u32 controller, u32 slot, u32 key);
            value = inpGetMidiCtrl(ctrl, state->midiSlot, state->midiEvent) & 0xffff;
        }
        else
        {
            value = 0;
        }
        return value & 0xffff;
    }
}

/*
 * Clamp and write an extended controller through MIDI for non-local controls.
 */
void inpSetExCtrl(McmdVoiceState* state, u32 ctrl, s16 value)
{
    int translated;
    int clamped;
    s16 v;

    if (value < 0)
    {
        clamped = 0;
    }
    else if (value > 0x3fff)
    {
        clamped = 0x3fff;
    }
    else
    {
        clamped = value;
    }
    v = clamped;
    translated = inpTranslateExCtrl(ctrl) & 0xff;
    if ((translated >= MCMD_CTRL_MIDI_LAYER || translated < MCMD_CTRL_EX_A0) &&
        state->midiSlot != 0xff)
    {
        inpSetMidiCtrl14(ctrl, state->midiSlot, state->midiEvent, v);
    }
}

/*
 * Pseudo-random number generator (linear congruential).
 *
 * EN v1.1 Address: 0x80282E5C, size 32b
 */
u16 sndRand(void)
{
    sndRandSeed = sndRandSeed * 0xA8351D63U;
    return (u16)((sndRandSeed >> 6) & 0xffff);
}

/*
 * Look up s16 from a 4-zone table based on the input's low 12 bits.
 * Upper two zones return sign-flipped values.
 *
 * EN v1.1 Address: 0x80282E7C, size 108b
 */
s16 sndSin(u32 packed)
{
    s16* table = sndSintab;
    u32 zone = packed & 0xfff;
    if (zone < 0x400)
    {
        return table[zone];
    }
    if (zone < 0x800)
    {
        u32 idx = 0x3ff - (zone & 0x3ff);
        return table[idx];
    }
    if (zone < 0xc00)
    {
        u32 idx = (zone & 0x3ff);
        return -table[idx];
    }
    {
        u32 idx = 0x3ff - (zone & 0x3ff);
        return -table[idx];
    }
}

/*
 * Binary search over fixed-stride sorted table entries.
 */
void* sndBSearch(void* key, void* base, int count, u32 stride, int (*cmp)(void*, void*))
{
    int high;
    int low;
    int mid;
    void* entry;
    int result;

    if (count != 0)
    {
        low = 1;
        high = count;
        do
        {
            mid = (low + high) >> 1;
            entry = (u8*)base + stride * (mid - 1);
            result = cmp(key, entry);
            if (result == 0)
            {
                return entry;
            }
            if (result < 0)
            {
                high = mid - 1;
            }
            else
            {
                low = mid + 1;
            }
        }
        while (low <= high);
    }
    return 0;
}

/*
 * Shift the value at *p left by 8 bits.
 *
 * EN v1.1 Address: 0x80282F80, size 16b
 */
void sndConvertMs(u32* p)
{
    *p = *p << 8;
}

/*
 * Compute a normalized scaled-1000-divided-by-32 value at *p using a
 * helper-derived divisor.
 *
 * EN v1.1 Address: 0x80282F90, size 72b
 */
void sndConvertTicks(u32* p, int x)
{
    int div = synthGetVoiceSlotChannelScale(x);
    *p = (((*p << 16) / div) * 0x3e8) >> 5;
}

/*
 * Right-shift by 8 (truncate ramp index).
 *
 * EN v1.1 Address: 0x80282FD8, size 8b
 */
u32 sndConvert2Ms(u32 x)
{
    return x >> 8;
}
