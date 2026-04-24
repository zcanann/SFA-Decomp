// Function: FUN_8023404c
// Entry: 8023404c
// Size: 892 bytes

void FUN_8023404c(short *param_1,char *param_2)

{
  uint uVar1;
  
  uVar1 = FUN_80014e70(0);
  if ((uVar1 & 0x10) != 0) {
    param_2[0xc] = param_2[0xc] ^ 1;
  }
  if (param_2[0xc] != '\0') {
    if ((uVar1 & 8) != 0) {
      param_2[0xd] = param_2[0xd] + '\x01';
    }
    if ((uVar1 & 4) != 0) {
      param_2[0xd] = param_2[0xd] + -1;
    }
    if ('\a' < param_2[0xd]) {
      param_2[0xd] = '\0';
    }
    if (param_2[0xd] < '\0') {
      param_2[0xd] = '\a';
    }
    switch(param_2[0xd]) {
    case '\0':
      if ((uVar1 & 1) != 0) {
        *param_1 = *param_1 + -1000;
      }
      if ((uVar1 & 2) != 0) {
        *param_1 = *param_1 + 1000;
      }
      FUN_80137948(s_Mode__YAW_8032ba00);
      FUN_80137948(s_Angle___d_8032ba0c,(int)*param_1);
      break;
    case '\x01':
      if ((uVar1 & 1) != 0) {
        param_1[1] = param_1[1] + -1000;
      }
      if ((uVar1 & 2) != 0) {
        param_1[1] = param_1[1] + 1000;
      }
      FUN_80137948(s_Mode__PITCH_8032ba18);
      FUN_80137948(s_Angle___d_8032ba0c,(int)param_1[1]);
      break;
    case '\x02':
      if ((uVar1 & 1) != 0) {
        *param_2 = *param_2 + -5;
      }
      if ((uVar1 & 2) != 0) {
        *param_2 = *param_2 + '\x05';
      }
      FUN_80137948(s_Mode__DIFFUSE_COLOUR_RED_8032ba28);
      FUN_80137948(s_Colour___d_8032ba44,*param_2);
      break;
    case '\x03':
      if ((uVar1 & 1) != 0) {
        param_2[1] = param_2[1] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[1] = param_2[1] + '\x05';
      }
      FUN_80137948(s_Mode__DIFFUSE_COLOUR_GREEN_8032ba50);
      FUN_80137948(s_Colour___d_8032ba44,param_2[1]);
      break;
    case '\x04':
      if ((uVar1 & 1) != 0) {
        param_2[2] = param_2[2] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[2] = param_2[2] + '\x05';
      }
      FUN_80137948(s_Mode__DIFFUSE_COLOUR_BLUE_8032ba6c);
      FUN_80137948(s_Colour___d_8032ba44,param_2[2]);
      break;
    case '\x05':
      if ((uVar1 & 1) != 0) {
        param_2[4] = param_2[4] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[4] = param_2[4] + '\x05';
      }
      FUN_80137948(s_Mode__SPECULAR_COLOUR_RED_8032ba88);
      FUN_80137948(s_Colour___d_8032ba44,param_2[4]);
      break;
    case '\x06':
      if ((uVar1 & 1) != 0) {
        param_2[5] = param_2[5] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[5] = param_2[5] + '\x05';
      }
      FUN_80137948(s_Mode__SPECULAR_COLOUR_GREEN_8032baa4);
      FUN_80137948(s_Colour___d_8032ba44,param_2[5]);
      break;
    case '\a':
      if ((uVar1 & 1) != 0) {
        param_2[6] = param_2[6] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[6] = param_2[6] + '\x05';
      }
      FUN_80137948(s_Mode__SPECULAR_COLOUR_BLUE_8032bac4);
      FUN_80137948(s_Colour___d_8032ba44,param_2[6]);
    }
  }
  return;
}

