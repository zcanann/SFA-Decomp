/*
 * modelAnimBuildJointMatrices -- retired C reconstruction.
 *
 * HISTORICAL RECONSTRUCTION: the live source is the function-level asm body in
 * src/main/render.c, which reproduces the retail bytes. This C draft reached
 * 15.515177% objdiff similarity and stays as a behaviour reference for the
 * packed-frame decoders, the polynomial sine/cosine, the quaternion blend and
 * the joint hierarchy pass. It compiled inside render.c with that unit's
 * includes; it is not a standalone translation unit. See joint_matrices.md.
 */

typedef struct RenderJointQuaternion {
    f32 w, x, y, z;
} RenderJointQuaternion;

/* The animation passes reuse each matrix slot for two interleaved poses. */
typedef union RenderJointWork {
    f32 matrix[4][4];
    RenderJointQuaternion quaternion[2];
    struct {
        u8 pad00[0x1C];
        s16 rotation[2][3];
        u16 scale[2][3];
        s16 translation[2][3];
    } pose;
} RenderJointWork;

STATIC_ASSERT(sizeof(RenderJointWork) == 0x40);
STATIC_ASSERT(offsetof(RenderJointWork, pose.rotation) == 0x1C);
STATIC_ASSERT(offsetof(RenderJointWork, pose.scale) == 0x28);
STATIC_ASSERT(offsetof(RenderJointWork, pose.translation) == 0x34);

typedef struct RenderJointBitstream {
    const u8* frame[2];
    u32 bits[2];
    int consumed;
} RenderJointBitstream;

extern s16 gModelRootRotX;
extern s16 gModelRootRotY;
extern s16 gModelRootRotZ;

static inline u32 render_jointReadWord(const u8* data) {
    return (u32)data[0] << 24 | (u32)data[1] << 16 | (u32)data[2] << 8 | data[3];
}

static inline void render_jointReadBits(RenderJointBitstream* stream, int width, int* first, int* second) {
    int advance;
    if (stream->consumed + width > 32) {
        advance = stream->consumed >> 3;
        stream->frame[0] += advance;
        stream->frame[1] += advance;
        stream->consumed &= 7;
        stream->bits[0] = render_jointReadWord(stream->frame[0]) << stream->consumed;
        stream->bits[1] = render_jointReadWord(stream->frame[1]) << stream->consumed;
    }
    *first = stream->bits[0] >> (32 - width);
    *second = stream->bits[1] >> (32 - width);
    stream->bits[0] <<= width;
    stream->bits[1] <<= width;
    stream->consumed += width;
}

static inline u16 render_jointPhase(f32 phase) {
    /* GQR3 stores an unsigned halfword, saturating before truncation. */
    if (phase <= 0.0f) {
        return 0;
    }
    if (phase >= 65535.0f) {
        return 65535;
    }
    return (u16)phase;
}

static inline int render_jointComponent(RenderJointBitstream* stream, u16 command, int shift, int fraction, int paired,
                                        int* second) {
    int firstDelta, secondDelta, difference;
    int width = command & 0xF;
    int base = command & (shift == 1 ? 0xFFC0 : 0xFFF0);
    if (width == 0) {
        /* The paired decoder retains the flag bits in constant scale words. */
        *second = paired ? command : base;
        return *second;
    }
    render_jointReadBits(stream, width, &firstDelta, &secondDelta);
    if (paired) {
        *second = base + (secondDelta << shift);
        return base + (firstDelta << shift);
    }
    difference = secondDelta - firstDelta;
    if (shift == 2) {
        difference = (s16)((u32)difference << 2) >> 2;
    } else if (shift == 0) {
        difference = (s16)difference;
    }
    firstDelta += (difference * fraction) >> 14;
    return base + firstDelta * (1 << shift);
}

static void render_jointDecode(RenderJointWork* work, int channel, const ObjAnimFrameHeader* header, const u8* frame,
                               s16 stride, f32 phase, const s16* adjustments, int paired) {
    RenderJointBitstream stream;
    const u16* command = header->trackDescriptors;
    int fraction = render_jointPhase((phase - render_jointPhase(phase)) * 16384.0f);
    int count = header->jointCount;
    int joint, axis, second;
    u16 rotation, scale;
    stream.frame[0] = frame;
    stream.frame[1] = frame + stride;
    stream.bits[0] = render_jointReadWord(stream.frame[0]);
    stream.bits[1] = render_jointReadWord(stream.frame[1]);
    stream.consumed = 0;
    for (joint = 0; joint < count; joint++) {
        for (axis = 0; axis < 3; axis++) {
            rotation = *command++;
            work[joint].pose.rotation[channel][axis] =
                render_jointComponent(&stream, rotation, 2, fraction, paired, &second);
            work[joint].pose.scale[channel][axis] = 0;
            work[joint].pose.translation[channel][axis] = 0;
            if (paired) {
                work[joint].pose.rotation[1][axis] = second;
                work[joint].pose.scale[1][axis] = 0;
                work[joint].pose.translation[1][axis] = 0;
            }
            if (rotation & 0x10) {
                scale = *command;
                if (scale & 0x10) {
                    command++;
                    work[joint].pose.scale[channel][axis] =
                        render_jointComponent(&stream, scale, 1, fraction, paired, &second);
                    if (paired) {
                        work[joint].pose.scale[1][axis] = second;
                    }
                    if (!(scale & 0x20)) {
                        continue;
                    }
                }
                work[joint].pose.translation[channel][axis] =
                    render_jointComponent(&stream, *command++, 0, fraction, paired, &second);
                if (paired) {
                    work[joint].pose.translation[1][axis] = second;
                }
            }
        }
    }
    while ((u16)adjustments[0] != 0x1000) {
        s16* value = (s16*)((u8*)work->pose.rotation[channel] + (u16)adjustments[0]);
        *value += adjustments[2];
        if (paired) {
            value[3] += adjustments[2];
        }
        adjustments += 4;
    }
}

static inline void render_jointSinCos(int angle, f32* sine, f32* cosine) {
    f32 x = (s16)(angle * 4);
    f32 square = x * x;
    f32 s, c;
    /* Coefficients in the retail pool at 803DE520..803DE540. */
    s = square * -8.844400411022846e-37f + 6.590635807686931e-26f;
    s = square * s + -2.2949214211376474e-15f;
    s = square * s + 2.396844865870662e-05f;
    s = x * s;
    c = square * 2.6554605898955283e-42f + -2.6329110382853367e-31f;
    c = square * c + 1.37514350128194e-20f;
    c = square * c + -2.872432847134121e-10f;
    c = square * c + 1.0f;
    switch ((angle + 0x2000) & 0xC000) {
    case 0:
        *sine = s;
        *cosine = c;
        break;
    case 0x4000:
        *sine = c;
        *cosine = -s;
        break;
    case 0x8000:
        *sine = -s;
        *cosine = -c;
        break;
    default:
        *sine = -c;
        *cosine = s;
        break;
    }
}

static inline void render_jointQuaternion(const s16* rotation, RenderJointQuaternion* result) {
    f32 sx, cx, sy, cy, sz, cz;
    f32 cc, cs, sc, ss;
    render_jointSinCos(rotation[0] >> 1, &sx, &cx);
    render_jointSinCos(rotation[1] >> 1, &sy, &cy);
    render_jointSinCos(rotation[2] >> 1, &sz, &cz);
    cc = cx * cy;
    cs = cx * sy;
    sc = sx * cy;
    ss = sx * sy;
    result->w = cc * cz + ss * sz;
    result->x = sc * cz - cs * sz;
    result->y = cs * cz + sc * sz;
    result->z = cc * sz - ss * cz;
}

static inline void render_jointStoreMatrix(RenderJointWork* output, const ModelBone* bone, const RenderJointWork* pose,
                                           int channel, f32 rotation[3][3], int blended) {
    int axis, row;
    u16 scale[3];
    s16 translation[3];
    /* Output may overlap the pose. Consume all packed components first. */
    for (axis = 0; axis < 3; axis++) {
        scale[axis] = pose->pose.scale[channel][axis];
        translation[axis] = pose->pose.translation[channel][axis];
    }
    for (axis = 0; axis < 3; axis++) {
        output->matrix[axis][3] = translation[axis] * (1.0f / 512.0f) + bone->head[axis];
    }
    for (axis = 0; axis < 3; axis++) {
        if (scale[axis] != 0) {
            f32 factor = scale[axis] * (1.0f / 1024.0f);
            for (row = 0; row < 3; row++) {
                output->matrix[row][axis] = rotation[row][axis] * factor;
            }
        } else if (blended && axis == 0) {
            /* Retail 800071FC stores this unscaled column across the first row. */
            output->matrix[0][0] = rotation[0][0];
            output->matrix[0][1] = rotation[1][0];
            output->matrix[0][2] = rotation[2][0];
        } else {
            for (row = 0; row < 3; row++) {
                output->matrix[row][axis] = rotation[row][axis];
            }
        }
    }
}

static inline void render_jointBlend(RenderJointWork* output, const ModelBone* bones, int count, RenderJointWork* first,
                                     int firstChannel, RenderJointWork* second, int secondChannel, int fraction,
                                     f32 weight, int flags, int mode) {
    RenderJointWork* blended = first;
    int blendedChannel = firstChannel;
    int joint, axis, firstIndex, secondIndex, blendIndex, index;
    int firstScale, secondScale, translation;
    f32 inverseWeight = 1.0f - weight;
    f32 dot, xx, xy, xz, yy, yz, zz, wx, wy, wz;
    f32 rotation[3][3];
    RenderJointQuaternion a, b, q;
    if (mode & 0x20) {
        second[0].pose.rotation[secondChannel][0] = gModelRootRotX;
        second[0].pose.rotation[secondChannel][1] = gModelRootRotY;
        second[0].pose.rotation[secondChannel][2] = gModelRootRotZ;
    }
    if (mode & 0xC) {
        blended = output;
        blendedChannel = (mode & 8) != 0;
    }
    for (joint = 0; joint < count; joint++) {
        firstIndex = bones[joint].idx[1];
        secondIndex = bones[joint].idx[2];
        blendIndex = firstIndex;
        if (mode & 0xF) {
            blendIndex = bones[joint].idx[0] & 0x7F;
            if (mode & 1) {
                firstIndex = blendIndex;
            } else if (mode & 2) {
                secondIndex = blendIndex;
            }
        }
        for (axis = 0; axis < 3; axis++) {
            firstScale = first[firstIndex].pose.scale[firstChannel][axis];
            secondScale = second[secondIndex].pose.scale[secondChannel][axis];
            if (firstScale == 0) {
                firstScale = 1024;
            }
            if (secondScale == 0) {
                secondScale = 1024;
            }
            blended[blendIndex].pose.scale[blendedChannel][axis] =
                firstScale + (((secondScale - firstScale) * fraction) >> 14);
            translation = first[firstIndex].pose.translation[firstChannel][axis];
            if (!(mode & 0x10)) {
                translation +=
                    ((second[secondIndex].pose.translation[secondChannel][axis] - translation) * fraction) >> 14;
            }
            blended[blendIndex].pose.translation[blendedChannel][axis] = translation;
        }
    }
    for (joint = 0; joint < count; joint++) {
        firstIndex = bones[joint].idx[1];
        secondIndex = bones[joint].idx[2];
        blendIndex = firstIndex;
        index = bones[joint].idx[0] & 0x7F;
        if (mode & 1) {
            a = output[index].quaternion[0];
            blendIndex = index;
        } else {
            render_jointQuaternion(first[firstIndex].pose.rotation[firstChannel], &a);
        }
        if (mode & 2) {
            b = output[index].quaternion[1];
        } else {
            render_jointQuaternion(second[secondIndex].pose.rotation[secondChannel], &b);
        }
        dot = a.w * b.w + a.x * b.x + a.y * b.y + a.z * b.z;
        if (dot < 0.0f) {
            b.w = -b.w;
            b.x = -b.x;
            b.y = -b.y;
            b.z = -b.z;
        }
        if (((s8)bones[joint].idx[0] & flags) < 0) {
            continue;
        }
        q.w = a.w * inverseWeight + b.w * weight;
        q.x = a.x * inverseWeight + b.x * weight;
        q.y = a.y * inverseWeight + b.y * weight;
        q.z = a.z * inverseWeight + b.z * weight;
        if (mode & 0xC) {
            output[index].quaternion[(mode & 8) != 0] = q;
            continue;
        }
        xx = q.x * (q.x * 2.0f);
        xy = q.x * (q.y * 2.0f);
        xz = q.x * (q.z * 2.0f);
        yy = q.y * (q.y * 2.0f);
        yz = q.y * (q.z * 2.0f);
        zz = q.z * (q.z * 2.0f);
        wx = q.w * (q.x * 2.0f);
        wy = q.w * (q.y * 2.0f);
        wz = q.w * (q.z * 2.0f);
        rotation[0][0] = 1.0f - (yy + zz);
        rotation[1][0] = xy + wz;
        rotation[2][0] = xz - wy;
        rotation[0][1] = xy - wz;
        rotation[1][1] = 1.0f - (xx + zz);
        rotation[2][1] = yz + wx;
        rotation[0][2] = xz + wy;
        rotation[1][2] = yz - wx;
        rotation[2][2] = 1.0f - (xx + yy);
        render_jointStoreMatrix(&output[index & flags], &bones[joint], &blended[blendIndex], blendedChannel, rotation,
                                1);
    }
}

static inline void render_jointSinglePose(RenderJointWork* output, const ModelBone* bones, int count,
                                          const RenderJointWork* pose, int flags) {
    int joint, index;
    f32 sx, cx, sy, cy, sz, cz;
    f32 cxsz, sxsz, sxcz, cxcz;
    f32 rotation[3][3];
    const s16* angles;
    for (joint = 0; joint < count; joint++) {
        index = (s8)bones[joint].idx[0] & flags;
        if (index < 0) {
            continue;
        }
        angles = pose[bones[joint].idx[1]].pose.rotation[0];
        render_jointSinCos(angles[0], &sx, &cx);
        render_jointSinCos(angles[1], &sy, &cy);
        render_jointSinCos(angles[2], &sz, &cz);
        cxsz = cx * sz;
        sxsz = sx * sz;
        sxcz = sx * cz;
        cxcz = cx * cz;
        rotation[0][0] = cy * cz;
        rotation[1][0] = cy * sz;
        rotation[2][0] = 0.0f - sy;
        rotation[0][1] = sxcz * sy - cxsz;
        rotation[1][1] = sxsz * sy + cxcz;
        rotation[2][1] = sx * cy;
        rotation[0][2] = cxcz * sy + sxsz;
        rotation[1][2] = cxsz * sy - sxcz;
        rotation[2][2] = cx * cy;
        render_jointStoreMatrix(&output[index], &bones[joint], &pose[bones[joint].idx[1]], 0, rotation, 0);
    }
}

static void render_jointHierarchy(RenderJointWork* output, const f32 root[4][4], const ModelBone* bones, int count,
                                  int flags) {
    f32 result[3][4];
    f32 parent[3][4];
    int joint, index, previous = -5, row, col;
    const f32(*source)[4];
    for (joint = 0; joint < count; joint++) {
        index = (s8)bones[joint].idx[0] & flags;
        if (index < 0) {
            previous = joint == 0 ? -5 : -1;
            continue;
        }
        if (joint == 0 || (u8)bones[joint].parent != previous) {
            source = joint == 0 ? root : output[(u8)bones[joint].parent].matrix;
            for (row = 0; row < 3; row++) {
                for (col = 0; col < 4; col++) {
                    parent[row][col] = source[row][col];
                }
            }
        }
        if (joint == 0) {
            index = bones[joint].idx[0] & 0x7F;
        }
        previous = index;
        for (row = 0; row < 3; row++) {
            for (col = 0; col < 4; col++) {
                f32 value = output[index].matrix[0][col] * parent[row][0];
                value = output[index].matrix[1][col] * parent[row][1] + value;
                value = output[index].matrix[2][col] * parent[row][2] + value;
                if (col == 3) {
                    value += parent[row][3];
                }
                result[row][col] = value;
            }
        }
        for (row = 0; row < 3; row++) {
            for (col = 0; col < 4; col++) {
                output[index].matrix[row][col] = result[row][col];
                parent[row][col] = result[row][col];
            }
        }
    }
}

void modelAnimBuildJointMatrices(int* out, u8* dst, void* animState, u8* jointData, int jointCount, u8* jointScratch,
                                 int flags, int mode) {
    RenderJointWork* output = *(RenderJointWork**)out;
    RenderJointWork* work = (RenderJointWork*)lbl_802C3564;
    RenderJointWork* first = work;
    RenderJointWork* second = work;
    ObjAnimState* anim = animState;
    const ModelBone* bones = (const ModelBone*)jointData;
    const s16* adjustments = (const s16*)jointScratch;
    int fraction = (s16)anim->eventCountdown;
    f32 weight = fraction / 16384.0f;
    if (mode & 0x40) {
        render_jointDecode(work, 0, anim->frameData[0], anim->frameStreamCursors[0], anim->frameStreamStrides[0],
                           anim->framePhases[0], adjustments, 1);
        weight = anim->framePhases[0] - render_jointPhase(anim->framePhases[0]);
        render_jointBlend(output, bones, jointCount, work, 0, work, 1, (s16)render_jointPhase(16384.0f * weight),
                          weight, flags, 4);
        /* A masked final joint exits the retail cache pass through the outer epilogue. */
        if (((s8)bones[jointCount - 1].idx[0] & flags) < 0) {
            return;
        }
        render_jointDecode(work, 1, anim->frameData[1], anim->frameStreamCursors[1], anim->frameStreamStrides[1],
                           anim->framePhases[1], adjustments, 0);
        weight = fraction / 16384.0f;
        mode = 1;
        first = output;
    } else {
        if (mode & 1) {
            first = output;
        } else {
            render_jointDecode(work, 0, anim->frameData[0], anim->frameStreamCursors[0], anim->frameStreamStrides[0],
                               anim->framePhases[0], adjustments, 0);
            if (fraction <= 0) {
                render_jointSinglePose(output, bones, jointCount, work, flags);
                if (!(mode & 0xC)) {
                    render_jointHierarchy(output, (const f32(*)[4])dst, bones, jointCount, flags);
                }
                return;
            }
        }
        if (mode & 2) {
            second = output;
        } else {
            render_jointDecode(work, 1, anim->frameData[1], anim->frameStreamCursors[1], anim->frameStreamStrides[1],
                               anim->framePhases[1], adjustments + 1, 0);
        }
    }
    render_jointBlend(output, bones, jointCount, first, 0, second, 1, fraction, weight, flags, mode);
    if (!(mode & 0xC)) {
        render_jointHierarchy(output, (const f32(*)[4])dst, bones, jointCount, flags);
    }
}
