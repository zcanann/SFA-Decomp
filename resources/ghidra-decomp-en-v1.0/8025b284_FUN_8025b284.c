// Function: FUN_8025b284
// Entry: 8025b284
// Size: 352 bytes

void FUN_8025b284(int param_1,float *param_2,char param_3)

{
  uint uVar1;
  
  if (param_1 != 8) {
    if (param_1 < 8) {
      if (param_1 != 4) {
        if (3 < param_1) {
          param_1 = param_1 + -5;
          goto LAB_8025b2d4;
        }
        if (0 < param_1) {
          param_1 = param_1 + -1;
          goto LAB_8025b2d4;
        }
      }
    }
    else if (param_1 < 0xc) {
      param_1 = param_1 + -9;
      goto LAB_8025b2d4;
    }
  }
  param_1 = 0;
LAB_8025b2d4:
  param_1 = param_1 * 3;
  uVar1 = (uint)(char)(param_3 + '\x11');
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (uVar1 & 3) << 0x16 |
                   (int)(FLOAT_803e76f8 * *param_2) & 0x7ffU |
                   ((int)(FLOAT_803e76f8 * param_2[3]) & 0x7ffU) << 0xb | (param_1 + 6) * 0x1000000)
  ;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (param_1 + 7) * 0x1000000 |
                   (uVar1 & 0xc) << 0x14 |
                   (int)(FLOAT_803e76f8 * param_2[1]) & 0x7ffU |
                   ((int)(FLOAT_803e76f8 * param_2[4]) & 0x7ffU) << 0xb);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (param_1 + 8) * 0x1000000 |
                   (uVar1 & 0x30) << 0x12 |
                   (int)(FLOAT_803e76f8 * param_2[2]) & 0x7ffU |
                   ((int)(FLOAT_803e76f8 * param_2[5]) & 0x7ffU) << 0xb);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

