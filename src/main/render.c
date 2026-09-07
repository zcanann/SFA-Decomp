#include "main/asset_load.h"
#include "main/dll/cloudaction_interface.h"
#include "main/mldf_fileid.h"
#include "main/model_engine.h"
#include "main/mm.h"
#include "main/newclouds.h"
#include "main/objanim_internal.h"
#include "main/pi_dolphin.h"
#include "main/render_envfx_api.h"
#include "main/render_internal.h"
#include "main/render_lactions_api.h"
#include "main/render_mode_api.h"
#include "main/render_sequence_api.h"
#include "main/sky_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"

static void render_copyPackedU64Tail(u64* dst, u32 packed);
static void render_copyPackedU64Head(u64* dst, u32 packed);

const int gModelRenderAdpcmStepTable[89] = {
    0x4,    0x8,    0x9,    0xA,    0xB,    0xC,    0xD,    0xE,    0x10,   0x11,   0x13,   0x15,   0x17,
    0x19,   0x1C,   0x1F,   0x22,   0x25,   0x29,   0x2D,   0x32,   0x37,   0x3C,   0x42,   0x49,   0x50,
    0x58,   0x61,   0x6B,   0x76,   0x82,   0x8F,   0x9D,   0xAD,   0xBE,   0xD1,   0xE6,   0xFD,   0x117,
    0x133,  0x151,  0x173,  0x198,  0x1C1,  0x1EE,  0x220,  0x256,  0x292,  0x2D4,  0x31C,  0x36C,  0x3C3,
    0x424,  0x48E,  0x502,  0x583,  0x610,  0x6AB,  0x756,  0x812,  0x8E0,  0x9C3,  0xABD,  0xBD0,  0xCFF,
    0xE4C,  0xFBA,  0x114C, 0x1307, 0x14EE, 0x1706, 0x1954, 0x1BDC, 0x1EA5, 0x21B6, 0x2515, 0x28CA, 0x2CDF,
    0x315B, 0x364B, 0x3BB9, 0x41B2, 0x4844, 0x4F7E, 0x5771, 0x602F, 0x69CE, 0x7462, 0x7FFF};
const int gModelRenderAdpcmIndexDeltaTable[17] = {-4, -2, -1, -1, 2, 4, 6, 8, -4, -2, -1, -1, 2, 4, 6, 8, 0};

// clang-format off
f32 gRenderSinTable[513] = {
    0.0f, 0.003068000078201294f, 0.006136000156402588f, 0.009204000234603882f, 0.012272000312805176f, 0.015339000150561333f, 0.018407000228762627f, 0.021474000066518784f,
    0.02454099990427494f, 0.027607999742031097f, 0.030674999579787254f, 0.03374100103974342f, 0.03680700063705444f, 0.03987300023436546f, 0.042938001453876495f, 0.04600299894809723f,
    0.04906800016760826f, 0.05213199928402901f, 0.055195000022649765f, 0.05825800076127052f, 0.06132100149989128f, 0.06438300013542175f, 0.06744399666786194f, 0.07050500065088272f,
    0.07356499880552292f, 0.07662399858236313f, 0.07968199998140335f, 0.08274000138044357f, 0.08579699695110321f, 0.08885399997234344f, 0.0919089987874031f, 0.09496299922466278f,
    0.09801699966192245f, 0.10107000172138214f, 0.10412199795246124f, 0.10717199742794037f, 0.1102219969034195f, 0.11327099800109863f, 0.11631900072097778f, 0.11936499923467636f,
    0.12241099774837494f, 0.12545500695705414f, 0.12849800288677216f, 0.13154000043869019f, 0.13458099961280823f, 0.1376200020313263f, 0.14065800607204437f, 0.14369499683380127f,
    0.14673000574111938f, 0.1497649997472763f, 0.15279699862003326f, 0.15582799911499023f, 0.15885800123214722f, 0.16188600659370422f, 0.16491299867630005f, 0.1679379940032959f,
    0.17096200585365295f, 0.17398400604724884f, 0.17700399458408356f, 0.18002299964427948f, 0.18303999304771423f, 0.1860550045967102f, 0.189069002866745f, 0.19208000600337982f,
    0.19508999586105347f, 0.19809800386428833f, 0.201104998588562f, 0.20410899817943573f, 0.20711100101470947f, 0.21011200547218323f, 0.21310999989509583f, 0.21610699594020844f,
    0.21910099685192108f, 0.22209399938583374f, 0.22508400678634644f, 0.22807200253009796f, 0.2310580015182495f, 0.2340420037508011f, 0.2370239943265915f, 0.24000300467014313f,
    0.2429800033569336f, 0.24595500528812408f, 0.2489279955625534f, 0.25189799070358276f, 0.25486600399017334f, 0.25783100724220276f, 0.2607940137386322f, 0.2637549936771393f,
    0.2667129933834076f, 0.26966801285743713f, 0.2726210057735443f, 0.2755720019340515f, 0.27851998805999756f, 0.28146499395370483f, 0.28440800309181213f, 0.2873469889163971f,
    0.29028499126434326f, 0.2932190001010895f, 0.2961510121822357f, 0.2990800142288208f, 0.3020060062408447f, 0.3049289882183075f, 0.3078500032424927f, 0.3107669949531555f,
    0.3136819899082184f, 0.3165929913520813f, 0.31950199604034424f, 0.322407990694046f, 0.32530999183654785f, 0.3282099962234497f, 0.3311060070991516f, 0.33399999141693115f,
    0.33689001202583313f, 0.33977699279785156f, 0.3426609933376312f, 0.34554100036621094f, 0.3484190106391907f, 0.35129299759864807f, 0.3541640043258667f, 0.357030987739563f,
    0.3598949909210205f, 0.36275601387023926f, 0.36561301350593567f, 0.3684670031070709f, 0.3713169991970062f, 0.37416398525238037f, 0.37700700759887695f, 0.37984699010849f,
    0.38268300890922546f, 0.3855159878730774f, 0.38834500312805176f, 0.3911699950695038f, 0.39399200677871704f, 0.39680999517440796f, 0.3996239900588989f, 0.4024350047111511f,
    0.4052410125732422f, 0.4080440104007721f, 0.41084301471710205f, 0.41363799571990967f, 0.4164299964904785f, 0.41921699047088623f, 0.421999990940094f, 0.424780011177063f,
    0.42755499482154846f, 0.43032601475715637f, 0.43309399485588074f, 0.43585699796676636f, 0.438616007566452f, 0.44137099385261536f, 0.44412198662757874f, 0.44686898589134216f,
    0.44961100816726685f, 0.452349990606308f, 0.4550839960575104f, 0.45781299471855164f, 0.4605390131473541f, 0.4632599949836731f, 0.4659770131111145f, 0.4686889946460724f,
    0.4713970124721527f, 0.4740999937057495f, 0.47679901123046875f, 0.47949400544166565f, 0.4821839928627014f, 0.48486900329589844f, 0.4875499904155731f, 0.49022701382637024f,
    0.49289798736572266f, 0.4955649971961975f, 0.4982280135154724f, 0.500885009765625f, 0.5035380125045776f, 0.5061870217323303f, 0.5088300108909607f, 0.5114690065383911f,
    0.5141029953956604f, 0.5167319774627686f, 0.5193560123443604f, 0.5219749808311462f, 0.524590015411377f, 0.5271989703178406f, 0.529803991317749f, 0.5324029922485352f,
    0.5349979996681213f, 0.5375869870185852f, 0.5401719808578491f, 0.5427510142326355f, 0.545324981212616f, 0.5478940010070801f, 0.5504580140113831f, 0.5530170202255249f,
    0.5555700063705444f, 0.558118999004364f, 0.5606619715690613f, 0.563198983669281f, 0.5657320022583008f, 0.5682590007781982f, 0.5707809925079346f, 0.5732970237731934f,
    0.5758079886436462f, 0.5783140063285828f, 0.580814003944397f, 0.58330899477005f, 0.5857980251312256f, 0.5882819890975952f, 0.5907599925994873f, 0.5932319760322571f,
    0.5956990122795105f, 0.598160982131958f, 0.6006159782409668f, 0.6030669808387756f, 0.6055110096931458f, 0.60794997215271f, 0.6103829741477966f, 0.6128100156784058f,
    0.615231990814209f, 0.6176469922065735f, 0.6200569868087769f, 0.6224610209465027f, 0.6248599886894226f, 0.6272519826889038f, 0.6296380162239075f, 0.6320189833641052f,
    0.6343929767608643f, 0.6367620229721069f, 0.6391239762306213f, 0.6414809823036194f, 0.6438320279121399f, 0.6461759805679321f, 0.6485139727592468f, 0.6508470177650452f,
    0.65317302942276f, 0.6554930210113525f, 0.6578069925308228f, 0.6601139903068542f, 0.6624159812927246f, 0.6647109985351562f, 0.6669999957084656f, 0.6692829728126526f,
    0.6715589761734009f, 0.6738290190696716f, 0.6760929822921753f, 0.6783499717712402f, 0.6806010007858276f, 0.6828460097312927f, 0.6850839853286743f, 0.6873149871826172f,
    0.6895409822463989f, 0.6917589902877808f, 0.6939709782600403f, 0.6961770057678223f, 0.6983759999275208f, 0.7005689740180969f, 0.7027549743652344f, 0.7049340009689331f,
    0.7071070075035095f, 0.7092729806900024f, 0.7114319801330566f, 0.7135850191116333f, 0.7157310247421265f, 0.7178699970245361f, 0.7200030088424683f, 0.7221279740333557f,
    0.7242469787597656f, 0.7263590097427368f, 0.7284640073776245f, 0.7305629849433899f, 0.7326539754867554f, 0.7347390055656433f, 0.7368170022964478f, 0.7388870120048523f,
    0.7409510016441345f, 0.743008017539978f, 0.745058000087738f, 0.7471010088920593f, 0.7491359710693359f, 0.751164972782135f, 0.7531870007514954f, 0.755200982093811f,
    0.7572090029716492f, 0.7592089772224426f, 0.7612019777297974f, 0.7631880044937134f, 0.7651669979095459f, 0.7671390175819397f, 0.7691029906272888f, 0.7710610032081604f,
    0.7730100154876709f, 0.7749530076980591f, 0.7768880128860474f, 0.7788159847259521f, 0.7807369828224182f, 0.7826510071754456f, 0.7845569849014282f, 0.786454975605011f,
    0.788345992565155f, 0.7902299761772156f, 0.7921069860458374f, 0.7939749956130981f, 0.7958369851112366f, 0.7976909875869751f, 0.7995370030403137f, 0.8013759851455688f,
    0.8032079935073853f, 0.8050310015678406f, 0.8068479895591736f, 0.8086559772491455f, 0.8104569911956787f, 0.8122509717941284f, 0.8140360116958618f, 0.8158140182495117f,
    0.8175849914550781f, 0.8193479776382446f, 0.8211020231246948f, 0.8228499889373779f, 0.8245890140533447f, 0.826321005821228f, 0.8280450105667114f, 0.8297610282897949f,
    0.8314700126647949f, 0.8331699967384338f, 0.834863007068634f, 0.8365479707717896f, 0.8382250070571899f, 0.8398939967155457f, 0.8415549993515015f, 0.8432080149650574f,
    0.8448539972305298f, 0.8464909791946411f, 0.8481199741363525f, 0.8497419953346252f, 0.8513550162315369f, 0.852961003780365f, 0.854557991027832f, 0.8561469912528992f,
    0.8577290177345276f, 0.8593019843101501f, 0.8608670234680176f, 0.8624240159988403f, 0.8639730215072632f, 0.8655139803886414f, 0.8670459985733032f, 0.8685709834098816f,
    0.8700870275497437f, 0.871595025062561f, 0.8730949759483337f, 0.8745869994163513f, 0.8760700225830078f, 0.8775449991226196f, 0.8790119886398315f, 0.8804709911346436f,
    0.8819209933280945f, 0.8833630084991455f, 0.8847969770431519f, 0.8862220048904419f, 0.8876399993896484f, 0.8890479803085327f, 0.8904489874839783f, 0.8918409943580627f,
    0.8932240009307861f, 0.8945990204811096f, 0.8959659934043884f, 0.8973249793052673f, 0.8986740112304688f, 0.9000160098075867f, 0.9013490080833435f, 0.9026730060577393f,
    0.9039890170097351f, 0.9052969813346863f, 0.9065960049629211f, 0.9078860282897949f, 0.909168004989624f, 0.910440981388092f, 0.9117059707641602f, 0.912962019443512f,
    0.9142100214958191f, 0.9154490232467651f, 0.9166790246963501f, 0.9179009795188904f, 0.9191139936447144f, 0.9203180074691772f, 0.9215139746665955f, 0.9227010011672974f,
    0.9238799810409546f, 0.9250490069389343f, 0.9262099862098694f, 0.9273629784584045f, 0.9285060167312622f, 0.9296410083770752f, 0.9307669997215271f, 0.9318839907646179f,
    0.9329929947853088f, 0.9340929985046387f, 0.9351840019226074f, 0.9362660050392151f, 0.9373390078544617f, 0.9384040236473083f, 0.9394590258598328f, 0.9405059814453125f,
    0.9415439963340759f, 0.9425730109214783f, 0.9435939788818359f, 0.9446049928665161f, 0.9456070065498352f, 0.9466009736061096f, 0.9475859999656677f, 0.9485610127449036f,
    0.9495279788970947f, 0.9504860043525696f, 0.9514350295066833f, 0.9523749947547913f, 0.9533060193061829f, 0.9542279839515686f, 0.955141007900238f, 0.9560449719429016f,
    0.9569399952888489f, 0.9578260183334351f, 0.9587029814720154f, 0.9595710039138794f, 0.9604309797286987f, 0.9612799882888794f, 0.9621210098266602f, 0.9629529714584351f,
    0.9637759923934937f, 0.9645900130271912f, 0.9653940200805664f, 0.966189980506897f, 0.9669770002365112f, 0.9677540063858032f, 0.9685220122337341f, 0.969281017780304f,
    0.9700310230255127f, 0.9707720279693604f, 0.9715039730072021f, 0.9722269773483276f, 0.9729400277137756f, 0.9736440181732178f, 0.9743390083312988f, 0.9750249981880188f,
    0.9757019877433777f, 0.9763699769973755f, 0.9770280122756958f, 0.9776769876480103f, 0.9783170223236084f, 0.9789479970932007f, 0.9795699715614319f, 0.9801819920539856f,
    0.9807850122451782f, 0.981378972530365f, 0.9819639921188354f, 0.9825389981269836f, 0.9831050038337708f, 0.9836620092391968f, 0.9842100143432617f, 0.9847480058670044f,
    0.9852780103683472f, 0.9857980012893677f, 0.9863079786300659f, 0.9868090152740479f, 0.9873009920120239f, 0.9877840280532837f, 0.9882580041885376f, 0.988722026348114f,
    0.9891769886016846f, 0.9896219968795776f, 0.9900580048561096f, 0.9904850125312805f, 0.9909030199050903f, 0.9913110136985779f, 0.9917100071907043f, 0.9920989871025085f,
    0.9924799799919128f, 0.9928500056266785f, 0.9932119846343994f, 0.9935640096664429f, 0.9939069747924805f, 0.9942399859428406f, 0.9945650100708008f, 0.9948790073394775f,
    0.9951850175857544f, 0.995481014251709f, 0.9957669973373413f, 0.9960449934005737f, 0.9963129758834839f, 0.9965710043907166f, 0.9968199729919434f, 0.9970600008964539f,
    0.9972900152206421f, 0.9975110292434692f, 0.9977229833602905f, 0.9979249835014343f, 0.998117983341217f, 0.9983019828796387f, 0.9984760284423828f, 0.9986400008201599f,
    0.9987949728965759f, 0.9989410042762756f, 0.9990779757499695f, 0.9992049932479858f, 0.9993219971656799f, 0.9994310140609741f, 0.9995290040969849f, 0.9996190071105957f,
    0.9996989965438843f, 0.9997689723968506f, 0.9998310208320618f, 0.9998819828033447f, 0.9999250173568726f, 0.9999579787254333f, 0.9999809861183167f, 0.9999949932098389f,
    1.0f};
// clang-format on
u8 lbl_802C3564[0x1964] = {0};

typedef struct EnvfxActEntry {
    u8 pad0[0x2a];
    u16 fadeDurationA;
    u8 pad1[0x30];
    u8 kind;
    u8 pad2[3];
} EnvfxActEntry;

int getLActions(void* source, void* target, u16 index, s8 arg3, int arg4, int arg5) {
    void* buf = mmAlloc(0x28, -1, 0);
    getTabEntry(buf, MLDF_FILEID_LACTIONS_BIN, index * 0x28, 0x28);
    mm_free(buf);
    return 0;
}

u8* modelRenderDecodeAdpcm(u8* compressed, int sampleCount, ModelRenderInstrsState* output, int bitStride,
                           u8 encodedBitWidth) {
    int predictor;
    int bitWidth = encodedBitWidth;
    int stepIndex;
    int initialOutputBit;
    int headerShift = bitWidth - 4;
    int predictorHeader = (*compressed >> 4) & 0xf;
    int i;
    u8 code;
    int difference;
    int step;
    int codeValue;
    u32 packedSample;
    int outputBit;
    int outputByte;
    u8* outputBytes;
    int packedShift;

    if (headerShift < 0) {
        headerShift = 0;
    }
    predictorHeader = predictorHeader << headerShift;
    predictor = predictorHeader;
    {
        int header = *(u8*)compressed;
        compressed += 1;
        stepIndex = (header & 0xf) << 3;
    }
    initialOutputBit = modelRenderInstrsState_getBit(output);
    bitStride -= bitWidth;
    packedShift = 0x10 - bitWidth;

    for (i = sampleCount / 2; i > 0; i--) {
        {
            code = *compressed & 0xf;
            step = gModelRenderAdpcmStepTable[stepIndex];
            difference = 0;
            codeValue = code;
            if (codeValue & 1) {
                difference = step >> 2;
            }
            if (codeValue & 2) {
                difference += step >> 1;
            }
            if (codeValue & 4) {
                difference += step;
            }
            if (codeValue & 8) {
                difference = -difference;
            }
            predictor += difference;
            stepIndex += gModelRenderAdpcmIndexDeltaTable[code];
            if (stepIndex < 0) {
                stepIndex = 0;
            } else if (stepIndex > 0x58) {
                stepIndex = 0x58;
            }
            packedSample = (u16)predictor;
            outputBit = output->bit;
            outputByte = outputBit >> 3;
            packedSample <<= ((8 - (outputBit & 7)) + packedShift);
            outputBytes = output->instrs;
            outputBytes[outputByte] |= (packedSample >> 16) & 0xff;
            outputBytes = output->instrs;
            outputBytes[outputByte + 1] |= (packedSample >> 8) & 0xff;
            outputBytes = output->instrs;
            outputBytes[outputByte + 2] |= packedSample & 0xff;
            output->bit += bitWidth;
            output->bit += bitStride;
        }

        {
            int difference;
            int step;
            int codeValue;

            code = (*compressed++ >> 4) & 0xf;
            step = gModelRenderAdpcmStepTable[stepIndex];
            difference = 0;
            codeValue = code;
            if (codeValue & 1) {
                difference = step >> 2;
            }
            if (codeValue & 2) {
                difference += step >> 1;
            }
            if (codeValue & 4) {
                difference += step;
            }
            if (codeValue & 8) {
                difference = -difference;
            }
            predictor += difference;
            stepIndex += gModelRenderAdpcmIndexDeltaTable[code];
            if (stepIndex < 0) {
                stepIndex = 0;
            } else if (stepIndex > 0x58) {
                stepIndex = 0x58;
            }
            {
                u32 packedSample;
                int outputBit;

                packedSample = (u16)predictor;
                outputBit = output->bit;
                outputByte = outputBit >> 3;
                packedSample <<= ((8 - (outputBit & 7)) + packedShift);
                outputBytes = output->instrs;
                outputBytes[outputByte] |= (packedSample >> 16) & 0xff;
                outputBytes = output->instrs;
                outputBytes[outputByte + 1] |= (packedSample >> 8) & 0xff;
                outputBytes = output->instrs;
                outputBytes[outputByte + 2] |= packedSample & 0xff;
                output->bit += bitWidth;
                output->bit += bitStride;
            }
        }
    }
    if (sampleCount & 1) {
        int difference;
        int step;
        int codeValue;

        code = *compressed++ & 0xf;
        step = gModelRenderAdpcmStepTable[stepIndex];
        difference = 0;
        codeValue = code;
        if (codeValue & 1) {
            difference = step >> 2;
        }
        if (codeValue & 2) {
            difference += step >> 1;
        }
        if (codeValue & 4) {
            difference += step;
        }
        if (codeValue & 8) {
            difference = -difference;
        }
        predictor += difference;
        stepIndex += gModelRenderAdpcmIndexDeltaTable[code];
        if (stepIndex < 0) {
            stepIndex = 0;
        } else if (stepIndex > 0x58) {
            stepIndex = 0x58;
        }
        {
            packedSample = (u16)predictor;
            outputBit = output->bit;
            outputByte = outputBit >> 3;
            packedSample <<= ((8 - (outputBit & 7)) + packedShift);
            outputBytes = output->instrs;
            outputBytes[outputByte] |= (packedSample >> 16) & 0xff;
            outputBytes = output->instrs;
            outputBytes[outputByte + 1] |= (packedSample >> 8) & 0xff;
            outputBytes = output->instrs;
            outputBytes[outputByte + 2] |= packedSample & 0xff;
            output->bit += bitWidth;
        }
    }
    if (bitStride != 0) {
        modelRenderInstrsState_setBit(output, initialOutputBit + bitWidth);
    }
    return compressed;
}

int modelRenderCopyPackedSamples(ModelRenderInstrsState* src, ModelRenderInstrsState* dst, int count, int gap,
                                 u8 bitWidth) {
    int startBit = modelRenderInstrsState_getBit(dst);
    u32 mask;
    int sh16;
    int i;
    int bw = bitWidth;

    mask = ~(-1 << bw);
    sh16 = 0x10 - bw;
    for (i = 0; i < count; i++) {
        int sByte;
        int sbit = src->bit;
        u32 val;
        u8* sp;
        u8* dp;
        int curBit;
        u32 packed;
        sByte = sbit >> 3;
        sp = (u8*)src->instrs + sByte;
        val = sp[0] << 16;
        val |= (sp[1] << 8);
        val |= sp[2];
        src->bit = sbit + bw;
        packed = mask & (val >> (sbit & 7));
        curBit = dst->bit;
        sByte = curBit >> 3;
        packed = packed << ((8 - (curBit & 7)) + sh16);
        dp = (u8*)dst->instrs;
        dp[sByte] |= (packed >> 16) & 0xff;
        dp = (u8*)dst->instrs;
        dp[sByte + 1] |= (packed >> 8) & 0xff;
        dp = (u8*)dst->instrs;
        dp[sByte + 2] |= packed & 0xff;
        dst->bit += bw;
        dst->bit += gap;
    }
    modelRenderInstrsState_setBit(dst, startBit + bw);
    {
        u8* base = (u8*)src->instrs;
        return base[(src->bit >> 3) + 1];
    }
}

s16 gModelRootRotZ;
s16 gModelRootRotY;
s16 gModelRootRotX;
static const ModelBone* sJointMatrixBones;
static struct {
    void* work;
    int* slot;
} sJointMatrixOutput = {NULL, NULL};
static u8 sJointMatrixScratch[0x100];
static const f32 sJointPairZeroOne[2] = {0.0f, 1.0f};
static const f32 sJointZero = 0.0f;
static const f32 sJointPhaseScale = 16384.0f;
static const f32 sJointOne = 1.0f;
static const f32 sJointTwo = 2.0f;
static const f32 sJointHalfScaleUnit = 0.001953125f;
static const f32 sJointScaleUnit = 0.0009765625f;
static const f32 sJointCosCoef8 = 2.65546059e-42f;
static const f32 sJointCosCoef6 = -2.63291104e-31f;
static const f32 sJointCosCoef4 = 1.3751435e-20f;
static const f32 sJointCosCoef2 = -2.87243285e-10f;
static const f32 sJointCosCoef0 = 1.0f;
static const f32 sJointSinCoef7 = -8.84440041e-37f;
static const f32 sJointSinCoef5 = 6.59063581e-26f;
static const f32 sJointSinCoef3 = -2.29492142e-15f;
static const f32 sJointSinCoef1 = 2.39684487e-05f;

// clang-format off
asm void modelAnimBuildJointMatrices(int* out, u8* dst, void* animState, u8* jointData, int jointCount, u8* jointScratch,
                                     int flags, int mode) {
    nofralloc
    mflr r0
    stwu r1, -0xfc(r1)
    stw r0, 0x100(r1)
    stfd f31, 0xf4(r1)
    stfd f30, 0xec(r1)
    stfd f29, 0xe4(r1)
    stfd f28, 0xdc(r1)
    stfd f27, 0xd4(r1)
    stfd f26, 0xcc(r1)
    stfd f25, 0xc4(r1)
    stfd f24, 0xbc(r1)
    stfd f23, 0xb4(r1)
    stfd f22, 0xac(r1)
    stfd f21, 0xa4(r1)
    stfd f20, 0x9c(r1)
    stfd f19, 0x94(r1)
    stfd f18, 0x8c(r1)
    stfd f17, 0x84(r1)
    stfd f16, 0x7c(r1)
    stfd f15, 0x74(r1)
    stfd f14, 0x6c(r1)
    stmw r14, 0x24(r1)
    stw r3, sJointMatrixOutput+4(r13)
    lwz r3, 0x0(r3)
    stw r3, sJointMatrixOutput(r13)
    stw r6, sJointMatrixBones(r13)
    lfs f30, sJointZero(r2)
    lis r11, lbl_802C3564@ha
    addi r11, r11, lbl_802C3564@l
    addi r11, r11, 0x1c
    addi r15, r11, 0x6
    andi. r17, r10, 0x40
    bne @cachePass
    mr r17, r10
    andi. r17, r17, 0x1
    beq @L_80006D08
    mr r11, r3
    addi r11, r11, 0x1c
    b @L_80006D38
@L_80006D08:
    stw r11, 0x8(r1)
    lwz r6, 0x34(r5)
    lwz r12, 0x2c(r5)
    lha r20, 0x4c(r5)
    lfs f4, 0x4(r5)
    mr r31, r11
    bl @decodeInterpolated
    lwz r11, 0x8(r1)
    lha r14, 0x58(r5)
    mr r24, r11
    cmpwi r14, 0x0
    ble @singlePose
@L_80006D38:
    mr r17, r10
    andi. r17, r17, 0x2
    beq @L_80006D50
    mr r15, r3
    addi r15, r15, 0x22
    b @L_80006D74
@L_80006D50:
    stw r11, 0x8(r1)
    lwz r6, 0x38(r5)
    lwz r12, 0x30(r5)
    lha r20, 0x4e(r5)
    lfs f4, 0x8(r5)
    mr r31, r15
    addi r8, r8, 0x2
    bl @decodeInterpolated
    lwz r11, 0x8(r1)
@L_80006D74:
    psq_l f20, 0x58(r5), 1, 5
    lha r16, 0x58(r5)
    lfs f21, sJointPhaseScale(r2)
    fdivs f28, f20, f21
    mr r31, r11
    mr r12, r15
    bl @blendJoints
    b @epilogue
@cachePass:
    lwz r6, 0x34(r5)
    lwz r12, 0x2c(r5)
    lha r20, 0x4c(r5)
    lfs f28, 0x4(r5)
    stw r11, 0x8(r1)
    mr r31, r11
    bl @decodePaired
    lwz r31, 0x8(r1)
    mr r12, r15
    psq_st f28, 0xc(r1), 1, 3
    psq_l f4, 0xc(r1), 1, 3
    fsubs f28, f28, f4
    lfs f21, sJointPhaseScale(r2)
    fmuls f21, f21, f28
    psq_st f21, 0xc(r1), 1, 3
    lha r16, 0xc(r1)
    li r19, 0x4
    mr r10, r19
    bl @blendJoints
    lis r11, lbl_802C3564@ha
    addi r11, r11, lbl_802C3564@l
    addi r11, r11, 0x1c
    addi r15, r11, 0x6
    lwz r6, 0x38(r5)
    lwz r12, 0x30(r5)
    lha r20, 0x4e(r5)
    lfs f4, 0x8(r5)
    mr r31, r15
    bl @decodeInterpolated
    psq_l f20, 0x58(r5), 1, 5
    lha r16, 0x58(r5)
    lfs f21, sJointPhaseScale(r2)
    fdivs f28, f20, f21
    li r19, 0x1
    mr r10, r19
    mr r31, r3
    addi r31, r31, 0x1c
    mr r12, r15
    bl @blendJoints
    b @epilogue
@blendJoints:
    mflr r29
    mr r19, r10
    andi. r18, r19, 0x20
    beq @L_80006E5C
    lha r11, gModelRootRotX(r13)
    sth r11, 0x0(r12)
    lha r11, gModelRootRotY(r13)
    sth r11, 0x2(r12)
    lha r11, gModelRootRotZ(r13)
    sth r11, 0x4(r12)
@L_80006E5C:
    mr r21, r31
    lwz r22, sJointMatrixBones(r13)
    mr r11, r7
    andi. r18, r19, 0xc
    beq @L_80006E84
    mr r21, r3
    addi r21, r21, 0x1c
    andi. r18, r18, 0x8
    beq @L_80006E84
    addi r21, r21, 0x6
@L_80006E84:
    li r23, 0x800
    li r14, 0x7fc
    lfs f31, sJointOne(r2)
    lfs f29, sJointTwo(r2)
    fsubs f27, f31, f28
    mulli r18, r11, 0x1c
    add r20, r18, r22
@L_80006EA0:
    lbz r18, 0x3(r22)
    slwi r17, r18, 6
    add r24, r12, r17
    lbz r18, 0x2(r22)
    slwi r15, r18, 6
    add r25, r31, r15
    add r26, r21, r15
    andi. r18, r19, 0xf
    li r11, 0x2
    beq @L_80006EF4
    lbz r18, 0x1(r22)
    andi. r18, r18, 0x7f
    slwi r15, r18, 6
    add r26, r21, r15
    andi. r18, r19, 0x3
    beq @L_80006EF4
    andi. r18, r18, 0x1
    beq @L_80006EF0
    add r25, r31, r15
    b @L_80006EF4
@L_80006EF0:
    add r24, r12, r15
@L_80006EF4:
    lhz r18, 0xc(r24)
    cmpwi r18, 0x0
    bne @L_80006F04
    ori r18, r18, 0x400
@L_80006F04:
    lhz r15, 0xc(r25)
    cmpwi r15, 0x0
    bne @L_80006F14
    ori r15, r15, 0x400
@L_80006F14:
    subf r18, r15, r18
    mullw r18, r18, r16
    srawi r18, r18, 14
    add r18, r18, r15
    sth r18, 0xc(r26)
    lha r15, 0x18(r25)
    addi r25, r25, 0x2
    andi. r18, r19, 0x10
    addi r24, r24, 0x2
    bne @L_80006F50
    lha r18, 0x16(r24)
    subf r18, r15, r18
    mullw r18, r18, r16
    srawi r18, r18, 14
    add r15, r15, r18
@L_80006F50:
    sth r15, 0x18(r26)
    addi r26, r26, 0x2
    mcrxr cr0
    cmpwi r11, 0x0
    addme r11, r11
    bne @L_80006EF4
    addi r22, r22, 0x1c
    cmpw r22, r20
    bne @L_80006EA0
    lis r27, gRenderSinTable@ha
    addi r27, r27, gRenderSinTable@l
    mr r11, r7
    lwz r22, sJointMatrixBones(r13)
    mr r28, r9
@L_80006F88:
    lbz r25, 0x2(r22)
    slwi r17, r25, 6
    add r24, r21, r17
    mr r18, r10
    andi. r15, r18, 0x1
    beq @L_80006FC8
    lbz r25, 0x1(r22)
    andi. r25, r25, 0x7f
    slwi r17, r25, 6
    add r16, r17, r3
    add r24, r21, r17
    lfs f20, 0x0(r16)
    lfs f21, 0x4(r16)
    lfs f25, 0x8(r16)
    lfs f26, 0xc(r16)
    b @L_80006FF0
@L_80006FC8:
    add r25, r31, r17
    bl @buildRotation
    fmuls f14, f7, f18
    fadds f20, f10, f11
    fmuls f15, f8, f19
    fsubs f21, f12, f13
    fmuls f16, f6, f19
    fadds f25, f14, f15
    fmuls f17, f9, f18
    fsubs f26, f16, f17
@L_80006FF0:
    lbz r25, 0x3(r22)
    slwi r17, r25, 6
    mr r18, r10
    andi. r15, r18, 0x2
    beq @L_8000702C
    lbz r25, 0x1(r22)
    andi. r25, r25, 0x7f
    slwi r17, r25, 6
    add r16, r17, r3
    addi r16, r16, 0x10
    lfs f4, 0x0(r16)
    lfs f5, 0x4(r16)
    lfs f6, 0x8(r16)
    lfs f7, 0xc(r16)
    b @L_80007054
@L_8000702C:
    add r25, r12, r17
    bl @buildRotation
    fmuls f14, f7, f18
    fadds f4, f10, f11
    fmuls f15, f8, f19
    fsubs f5, f12, f13
    fmuls f16, f6, f19
    fadds f6, f14, f15
    fmuls f17, f9, f18
    fsubs f7, f16, f17
@L_80007054:
    fmuls f10, f20, f4
    fmuls f11, f21, f5
    fmuls f12, f25, f6
    fadds f10, f10, f11
    fmuls f13, f26, f7
    fadds f10, f10, f12
    fmuls f20, f20, f27
    fadds f10, f10, f13
    fmuls f21, f21, f27
    fcmpo cr0, f10, f30
    fmuls f25, f25, f27
    bge @L_80007094
    fsubs f4, f30, f4
    fsubs f5, f30, f5
    fsubs f6, f30, f6
    fsubs f7, f30, f7
@L_80007094:
    fmuls f26, f26, f27
    fmuls f4, f4, f28
    lbz r20, 0x1(r22)
    slwi r20, r20, 24
    srawi r20, r20, 24
    and. r20, r20, r28
    bge @L_800070C4
    mcrxr cr0
    addme. r11, r11
    addi r22, r22, 0x1c
    bne @L_80006F88
    b @hierarchy
@L_800070C4:
    andi. r20, r20, 0x7f
    fmuls f5, f5, f28
    fadds f10, f20, f4
    fmuls f6, f6, f28
    fadds f11, f21, f5
    fmuls f7, f7, f28
    fadds f12, f25, f6
    fmuls f0, f11, f29
    fadds f13, f26, f7
    mr r18, r10
    andi. r17, r18, 0xc
    beq @L_8000713C
    lbz r25, 0x1(r22)
    andi. r25, r25, 0x7f
    slwi r17, r25, 6
    mr r25, r3
    andi. r18, r18, 0x8
    beq @L_80007110
    addi r25, r25, 0x10
@L_80007110:
    add r17, r17, r25
    stfs f10, 0x0(r17)
    stfs f11, 0x4(r17)
    stfs f12, 0x8(r17)
    stfs f13, 0xc(r17)
    mcrxr cr0
    addme. r11, r11
    addi r22, r22, 0x1c
    bne @L_80006F88
    mtlr r29
    blr
@L_8000713C:
    fmuls f1, f12, f29
    slwi r20, r20, 6
    lwz r15, sJointMatrixOutput(r13)
    add r15, r15, r20
    lfs f2, sJointHalfScaleUnit(r2)
    psq_l f6, 0x18(r24), 1, 5
    lfs f7, 0x4(r22)
    fmuls f6, f6, f2
    fadds f3, f6, f7
    psq_l f6, 0x1a(r24), 1, 5
    lfs f7, 0x8(r22)
    fmuls f8, f6, f2
    fadds f8, f8, f7
    psq_l f6, 0x1c(r24), 1, 5
    lfs f7, 0xc(r22)
    fmuls f6, f6, f2
    lhz r18, 0xc(r24)
    lhz r16, 0xe(r24)
    lhz r25, 0x10(r24)
    stfs f3, 0xc(r15)
    fmuls f2, f13, f29
    fadds f6, f6, f7
    fmuls f3, f10, f0
    stfs f6, 0x2c(r15)
    fmuls f4, f10, f1
    stfs f8, 0x1c(r15)
    fmuls f5, f10, f2
    fmuls f6, f11, f0
    fmuls f7, f11, f1
    fmuls f8, f11, f2
    fadds f20, f7, f5
    fmuls f17, f13, f2
    fsubs f21, f8, f4
    fmuls f15, f12, f1
    fadds f25, f8, f4
    fmuls f16, f12, f2
    fadds f19, f15, f17
    fsubs f19, f31, f19
    fsubs f26, f16, f3
    fadds f10, f6, f15
    fsubs f10, f31, f10
    fadds f4, f16, f3
    fsubs f2, f7, f5
    fadds f3, f6, f17
    fsubs f3, f31, f3
    lfs f1, sJointScaleUnit(r2)
    cmpwi r18, 0x0
    bne @L_80007244
    stfs f19, 0x0(r15)
    stfs f20, 0x4(r15)
    stfs f21, 0x8(r15)
    cmpwi r16, 0x0
    bne @L_80007270
@L_80007210:
    stfs f2, 0x4(r15)
    stfs f3, 0x14(r15)
    stfs f4, 0x24(r15)
    cmpwi r25, 0x0
    bne @L_8000729C
@L_80007224:
    stfs f25, 0x8(r15)
    stfs f26, 0x18(r15)
    stfs f10, 0x28(r15)
@L_80007230:
    mcrxr cr0
    addme. r11, r11
    addi r22, r22, 0x1c
    bne @L_80006F88
    b @hierarchy
@L_80007244:
    sth r18, 0xc(r1)
    psq_l f0, 0xc(r1), 1, 3
    fmuls f0, f0, f1
    fmuls f19, f19, f0
    stfs f19, 0x0(r15)
    fmuls f20, f20, f0
    stfs f20, 0x10(r15)
    fmuls f21, f21, f0
    stfs f21, 0x20(r15)
    cmpwi r16, 0x0
    beq @L_80007210
@L_80007270:
    sth r16, 0xc(r1)
    psq_l f0, 0xc(r1), 1, 3
    fmuls f0, f0, f1
    fmuls f2, f2, f0
    stfs f2, 0x4(r15)
    fmuls f3, f3, f0
    stfs f3, 0x14(r15)
    fmuls f4, f4, f0
    stfs f4, 0x24(r15)
    cmpwi r25, 0x0
    beq @L_80007224
@L_8000729C:
    sth r25, 0xc(r1)
    psq_l f0, 0xc(r1), 1, 3
    fmuls f0, f0, f1
    fmuls f25, f25, f0
    stfs f25, 0x8(r15)
    fmuls f26, f26, f0
    stfs f26, 0x18(r15)
    fmuls f10, f10, f0
    stfs f10, 0x28(r15)
    b @L_80007230
@buildRotation:
    mflr r0
    stwu r1, -0x34(r1)
    stw r0, 0x38(r1)
    stfs f23, 0x10(r1)
    stfs f24, 0x14(r1)
    stfs f25, 0x18(r1)
    stfs f26, 0x1c(r1)
    stfs f27, 0x20(r1)
    stfs f28, 0x24(r1)
    stfs f29, 0x28(r1)
    stfs f30, 0x2c(r1)
    stfs f31, 0x30(r1)
    lfs f31, sJointCosCoef8(r2)
    lfs f30, sJointCosCoef6(r2)
    lfs f29, sJointCosCoef4(r2)
    lfs f28, sJointCosCoef2(r2)
    lfs f27, sJointCosCoef0(r2)
    lfs f26, sJointSinCoef7(r2)
    lfs f25, sJointSinCoef5(r2)
    lfs f24, sJointSinCoef3(r2)
    lfs f23, sJointSinCoef1(r2)
    lha r16, 0x0(r25)
    srawi r16, r16, 1
    slwi r15, r16, 2
    sth r15, 0xc(r1)
    psq_l f9, 0xc(r1), 1, 5
    fmuls f8, f9, f9
    fmadds f7, f8, f26, f25
    fmadds f7, f8, f7, f24
    fmadds f7, f8, f7, f23
    fmuls f7, f9, f7
    fmadds f6, f8, f31, f30
    fmadds f6, f8, f6, f29
    fmadds f6, f8, f6, f28
    fmadds f6, f8, f6, f27
    addi r15, r16, 0x2000
    andi. r15, r15, 0xc000
    beq @L_80007378
    cmpwi r15, 0x4000
    beq @L_80007384
    cmplwi r15, 0x8000
    beq @L_80007390
    fneg f1, f6
    fmr f0, f7
    b @L_80007398
@L_80007378:
    fmr f1, f7
    fmr f0, f6
    b @L_80007398
@L_80007384:
    fmr f1, f6
    fneg f0, f7
    b @L_80007398
@L_80007390:
    fneg f1, f7
    fneg f0, f6
@L_80007398:
    lha r16, 0x2(r25)
    srawi r16, r16, 1
    slwi r15, r16, 2
    sth r15, 0xc(r1)
    psq_l f9, 0xc(r1), 1, 5
    fmuls f8, f9, f9
    fmadds f7, f8, f26, f25
    fmadds f7, f8, f7, f24
    fmadds f7, f8, f7, f23
    fmuls f7, f9, f7
    fmadds f6, f8, f31, f30
    fmadds f6, f8, f6, f29
    fmadds f6, f8, f6, f28
    fmadds f6, f8, f6, f27
    addi r15, r16, 0x2000
    andi. r15, r15, 0xc000
    beq @L_800073F8
    cmpwi r15, 0x4000
    beq @L_80007404
    cmplwi r15, 0x8000
    beq @L_80007410
    fneg f3, f6
    fmr f2, f7
    b @L_80007418
@L_800073F8:
    fmr f3, f7
    fmr f2, f6
    b @L_80007418
@L_80007404:
    fmr f3, f6
    fneg f2, f7
    b @L_80007418
@L_80007410:
    fneg f3, f7
    fneg f2, f6
@L_80007418:
    lha r16, 0x4(r25)
    srawi r16, r16, 1
    slwi r15, r16, 2
    sth r15, 0xc(r1)
    psq_l f9, 0xc(r1), 1, 5
    fmuls f8, f9, f9
    fmadds f7, f8, f26, f25
    fmadds f7, f8, f7, f24
    fmadds f7, f8, f7, f23
    fmuls f7, f9, f7
    fmadds f6, f8, f31, f30
    fmadds f6, f8, f6, f29
    fmadds f6, f8, f6, f28
    fmadds f6, f8, f6, f27
    addi r15, r16, 0x2000
    andi. r15, r15, 0xc000
    beq @L_80007478
    cmpwi r15, 0x4000
    beq @L_80007484
    cmplwi r15, 0x8000
    beq @L_80007490
    fneg f19, f6
    fmr f18, f7
    b @L_80007498
@L_80007478:
    fmr f19, f7
    fmr f18, f6
    b @L_80007498
@L_80007484:
    fmr f19, f6
    fneg f18, f7
    b @L_80007498
@L_80007490:
    fneg f19, f7
    fneg f18, f6
@L_80007498:
    fmuls f6, f0, f2
    fmuls f7, f0, f3
    fmuls f8, f1, f2
    fmuls f9, f1, f3
    fmuls f10, f6, f18
    fmuls f11, f9, f19
    fmuls f12, f8, f18
    fmuls f13, f7, f19
    lfs f23, 0x10(r1)
    lfs f24, 0x14(r1)
    lfs f25, 0x18(r1)
    lfs f26, 0x1c(r1)
    lfs f27, 0x20(r1)
    lfs f28, 0x24(r1)
    lfs f29, 0x28(r1)
    lfs f30, 0x2c(r1)
    lfs f31, 0x30(r1)
    lwz r0, 0x38(r1)
    mtlr r0
    addi r1, r1, 0x34
    blr
@decodeInterpolated:
    mr r22, r31
    addi r14, r6, 0x4
    lbz r16, 0x0(r6)
    add r20, r20, r12
    psq_st f4, 0xc(r1), 1, 3
    psq_l f6, 0xc(r1), 1, 3
    fsubs f4, f4, f6
    lfs f5, sJointPhaseScale(r2)
    fmuls f6, f4, f5
    psq_st f6, 0xc(r1), 1, 3
    lhz r29, 0xc(r1)
    slwi r19, r16, 1
    add r16, r16, r19
    li r23, 0x20
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    li r27, 0x0
    li r18, 0x3
@L_80007534:
    lhz r26, 0x0(r14)
    andi. r17, r26, 0xf
    andi. r25, r26, 0xfff0
    cmpwi r17, 0x0
    beq @L_800075B0
    add r27, r27, r17
    cmpwi r27, 0x20
    ble @L_8000757C
    subf r27, r17, r27
    srwi r19, r27, 3
    add r12, r12, r19
    add r20, r20, r19
    andi. r27, r27, 0x7
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    slw r19, r19, r27
    slw r28, r28, r27
    add r27, r27, r17
@L_8000757C:
    subf r24, r17, r23
    srw r30, r19, r24
    srw r24, r28, r24
    subf r24, r30, r24
    slwi r24, r24, 18
    srawi r24, r24, 18
    mullw r24, r24, r29
    srawi r24, r24, 14
    add r30, r30, r24
    slwi r30, r30, 2
    add r25, r25, r30
    slw r19, r19, r17
    slw r28, r28, r17
@L_800075B0:
    sth r25, 0x0(r31)
    addi r14, r14, 0x2
    stw r14, 0xc(r1)
    li r14, 0x0
    sth r14, 0xc(r31)
    sth r14, 0x18(r31)
    lwz r14, 0xc(r1)
    andi. r25, r26, 0x10
    bne @L_80007624
@L_800075D4:
    mcrxr cr0
    addme. r18, r18
    bne @L_800075E8
    li r18, 0x3
    addi r31, r31, 0x3a
@L_800075E8:
    addi r31, r31, 0x2
    mcrxr cr0
    addme. r16, r16
    bne @L_80007534
    mr r19, r8
@L_800075FC:
    lhz r25, 0x0(r19)
    cmpwi r25, 0x1000
    beqlr
    add r25, r25, r22
    lha r30, 0x0(r25)
    lha r24, 0x4(r19)
    add r30, r30, r24
    sth r30, 0x0(r25)
    addi r19, r19, 0x8
    b @L_800075FC
@L_80007624:
    lhz r26, 0x0(r14)
    andi. r17, r26, 0x10
    beq @L_800076B8
    andi. r25, r26, 0xffc0
    andi. r11, r26, 0x20
    andi. r17, r26, 0xf
    beq @L_800076A0
    add r27, r27, r17
    cmpwi r27, 0x20
    ble @L_80007674
    subf r27, r17, r27
    srwi r19, r27, 3
    add r12, r12, r19
    add r20, r20, r19
    andi. r27, r27, 0x7
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    slw r19, r19, r27
    slw r28, r28, r27
    add r27, r27, r17
@L_80007674:
    subf r24, r17, r23
    srw r30, r19, r24
    srw r24, r28, r24
    subf r24, r30, r24
    mullw r24, r24, r29
    srawi r24, r24, 14
    add r30, r30, r24
    slwi r30, r30, 1
    add r25, r25, r30
    slw r19, r19, r17
    slw r28, r28, r17
@L_800076A0:
    sth r25, 0xc(r31)
    addi r14, r14, 0x2
    lhz r26, 0x0(r14)
    cmpwi r11, 0x0
    bne @L_800076B8
    b @L_800075D4
@L_800076B8:
    andi. r25, r26, 0xfff0
    andi. r17, r26, 0xf
    beq @L_8000772C
    add r27, r27, r17
    cmpwi r27, 0x20
    ble @L_800076F8
    subf r27, r17, r27
    srwi r19, r27, 3
    add r12, r12, r19
    add r20, r20, r19
    andi. r27, r27, 0x7
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    slw r19, r19, r27
    slw r28, r28, r27
    add r27, r27, r17
@L_800076F8:
    subf r24, r17, r23
    srw r30, r19, r24
    srw r24, r28, r24
    subf r24, r30, r24
    slwi r24, r24, 16
    srawi r24, r24, 16
    mullw r24, r24, r29
    srawi r24, r24, 14
    add r30, r30, r24
    rlwinm r30, r30, 0, 0, 31
    add r25, r25, r30
    slw r19, r19, r17
    slw r28, r28, r17
@L_8000772C:
    sth r25, 0x18(r31)
    addi r14, r14, 0x2
    b @L_800075D4
@decodePaired:
    mr r22, r31
    addi r14, r6, 0x4
    lbz r16, 0x0(r6)
    add r20, r20, r12
    slwi r19, r16, 1
    add r16, r16, r19
    li r23, 0x20
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    li r27, 0x0
    li r18, 0x3
@L_80007764:
    lhz r25, 0x0(r14)
    andi. r17, r25, 0xf
    bne @L_8000777C
    sth r25, 0x0(r31)
    sth r25, 0x6(r31)
    b @L_800077E0
@L_8000777C:
    andi. r25, r25, 0xfff0
    add r27, r27, r17
    cmpwi r27, 0x20
    ble @L_800077B4
    subf r27, r17, r27
    srwi r19, r27, 3
    add r12, r12, r19
    add r20, r20, r19
    andi. r27, r27, 0x7
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    slw r19, r19, r27
    slw r28, r28, r27
    add r27, r27, r17
@L_800077B4:
    subf r24, r17, r23
    srw r30, r19, r24
    srw r24, r28, r24
    slwi r30, r30, 2
    add r30, r30, r25
    slwi r24, r24, 2
    add r24, r24, r25
    slw r19, r19, r17
    slw r28, r28, r17
    sth r30, 0x0(r31)
    sth r24, 0x6(r31)
@L_800077E0:
    addi r14, r14, 0x2
    stw r14, 0xc(r1)
    li r14, 0x0
    sth r14, 0xc(r31)
    sth r14, 0x12(r31)
    sth r14, 0x18(r31)
    sth r14, 0x1e(r31)
    lwz r14, 0xc(r1)
    andi. r25, r25, 0x10
    bne @L_80007864
@L_80007808:
    mcrxr cr0
    addme. r18, r18
    bne @L_8000781C
    li r18, 0x3
    addi r31, r31, 0x3a
@L_8000781C:
    addi r31, r31, 0x2
    mcrxr cr0
    addme. r16, r16
    bne @L_80007764
    mr r19, r8
@L_80007830:
    lhz r25, 0x0(r19)
    cmpwi r25, 0x1000
    beqlr
    add r25, r25, r22
    lha r30, 0x0(r25)
    lha r24, 0x4(r19)
    add r30, r30, r24
    sth r30, 0x0(r25)
    lha r30, 0x6(r25)
    add r30, r30, r24
    sth r30, 0x6(r25)
    addi r19, r19, 0x8
    b @L_80007830
@L_80007864:
    lhz r25, 0x0(r14)
    andi. r17, r25, 0x10
    beq @L_80007900
    andi. r11, r25, 0x20
    andi. r17, r25, 0xf
    bne @L_80007888
    sth r25, 0xc(r31)
    sth r25, 0x12(r31)
    b @L_800078EC
@L_80007888:
    andi. r25, r25, 0xffc0
    add r27, r27, r17
    cmpwi r27, 0x20
    ble @L_800078C0
    subf r27, r17, r27
    srwi r19, r27, 3
    add r12, r12, r19
    add r20, r20, r19
    andi. r27, r27, 0x7
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    slw r19, r19, r27
    slw r28, r28, r27
    add r27, r27, r17
@L_800078C0:
    subf r24, r17, r23
    srw r30, r19, r24
    srw r24, r28, r24
    slwi r30, r30, 1
    add r30, r30, r25
    slwi r24, r24, 1
    add r24, r24, r25
    slw r19, r19, r17
    slw r28, r28, r17
    sth r30, 0xc(r31)
    sth r24, 0x12(r31)
@L_800078EC:
    addi r14, r14, 0x2
    lhz r25, 0x0(r14)
    cmpwi r11, 0x0
    bne @L_80007900
    b @L_80007808
@L_80007900:
    andi. r17, r25, 0xf
    bne @L_80007914
    sth r25, 0x18(r31)
    sth r25, 0x1e(r31)
    b @L_80007978
@L_80007914:
    andi. r25, r25, 0xfff0
    add r27, r27, r17
    cmpwi r27, 0x20
    ble @L_8000794C
    subf r27, r17, r27
    srwi r19, r27, 3
    add r12, r12, r19
    add r20, r20, r19
    andi. r27, r27, 0x7
    lwz r19, 0x0(r12)
    lwz r28, 0x0(r20)
    slw r19, r19, r27
    slw r28, r28, r27
    add r27, r27, r17
@L_8000794C:
    subf r24, r17, r23
    srw r30, r19, r24
    srw r24, r28, r24
    rlwinm r30, r30, 0, 0, 31
    add r30, r30, r25
    rlwinm r24, r24, 0, 0, 31
    add r24, r24, r25
    slw r19, r19, r17
    slw r28, r28, r17
    sth r30, 0x18(r31)
    sth r24, 0x1e(r31)
@L_80007978:
    addi r14, r14, 0x2
    b @L_80007808
@singlePose:
    lwz r22, sJointMatrixBones(r13)
    lwz r6, sJointMatrixOutput(r13)
    mr r25, r7
    mulli r25, r25, 0x1c
    add r30, r25, r22
    mr r25, r9
    li r27, 0x200
    li r19, 0x400
    li r20, 0x600
    lfs f21, sJointScaleUnit(r2)
    lfs f29, sJointHalfScaleUnit(r2)
    li r14, 0x7fc
    li r23, 0x800
    lis r31, gRenderSinTable@ha
    addi r31, r31, gRenderSinTable@l
@singlePoseJoint:
    lbz r15, 0x1(r22)
    slwi r15, r15, 24
    srawi r15, r15, 24
    and. r15, r15, r25
    bge @L_800079E4
    addi r22, r22, 0x1c
    nop
    cmpw r22, r30
    bne @singlePoseJoint
    b @hierarchy
@L_800079E4:
    slwi r18, r15, 6
    lbz r15, 0x2(r22)
    add r3, r18, r6
    slwi r11, r15, 6
    add r28, r24, r11
    lis r18, sJointMatrixScratch@ha
    addi r18, r18, sJointMatrixScratch@l
    stfs f23, 0x0(r18)
    stfs f24, 0x4(r18)
    stfs f25, 0x8(r18)
    stfs f26, 0xc(r18)
    stfs f27, 0x10(r18)
    stfs f28, 0x14(r18)
    stfs f29, 0x18(r18)
    stfs f30, 0x1c(r18)
    stfs f31, 0x20(r18)
    lfs f31, sJointCosCoef8(r2)
    lfs f30, sJointCosCoef6(r2)
    lfs f29, sJointCosCoef4(r2)
    lfs f28, sJointCosCoef2(r2)
    lfs f27, sJointCosCoef0(r2)
    lfs f26, sJointSinCoef7(r2)
    lfs f25, sJointSinCoef5(r2)
    lfs f24, sJointSinCoef3(r2)
    lfs f23, sJointSinCoef1(r2)
    lhz r16, 0x0(r28)
    slwi r15, r16, 2
    sth r15, 0x24(r18)
    psq_l f9, 0x24(r18), 1, 5
    fmuls f8, f9, f9
    fmadds f7, f8, f26, f25
    fmadds f7, f8, f7, f24
    fmadds f7, f8, f7, f23
    fmuls f7, f9, f7
    fmadds f6, f8, f31, f30
    fmadds f6, f8, f6, f29
    fmadds f6, f8, f6, f28
    fmadds f6, f8, f6, f27
    addi r15, r16, 0x2000
    andi. r15, r15, 0xc000
    beq @L_80007AA4
    cmpwi r15, 0x4000
    beq @L_80007AB0
    cmplwi r15, 0x8000
    beq @L_80007ABC
    fneg f1, f6
    fmr f0, f7
    b @L_80007AC4
@L_80007AA4:
    fmr f1, f7
    fmr f0, f6
    b @L_80007AC4
@L_80007AB0:
    fmr f1, f6
    fneg f0, f7
    b @L_80007AC4
@L_80007ABC:
    fneg f1, f7
    fneg f0, f6
@L_80007AC4:
    lhz r16, 0x2(r28)
    slwi r15, r16, 2
    sth r15, 0x24(r18)
    psq_l f9, 0x24(r18), 1, 5
    fmuls f8, f9, f9
    fmadds f7, f8, f26, f25
    fmadds f7, f8, f7, f24
    fmadds f7, f8, f7, f23
    fmuls f7, f9, f7
    fmadds f6, f8, f31, f30
    fmadds f6, f8, f6, f29
    fmadds f6, f8, f6, f28
    fmadds f6, f8, f6, f27
    addi r15, r16, 0x2000
    andi. r15, r15, 0xc000
    beq @L_80007B20
    cmpwi r15, 0x4000
    beq @L_80007B2C
    cmplwi r15, 0x8000
    beq @L_80007B38
    fneg f3, f6
    fmr f2, f7
    b @L_80007B40
@L_80007B20:
    fmr f3, f7
    fmr f2, f6
    b @L_80007B40
@L_80007B2C:
    fmr f3, f6
    fneg f2, f7
    b @L_80007B40
@L_80007B38:
    fneg f3, f7
    fneg f2, f6
@L_80007B40:
    lhz r16, 0x4(r28)
    slwi r15, r16, 2
    sth r15, 0x24(r18)
    psq_l f9, 0x24(r18), 1, 5
    fmuls f8, f9, f9
    fmadds f7, f8, f26, f25
    fmadds f7, f8, f7, f24
    fmadds f7, f8, f7, f23
    fmuls f7, f9, f7
    fmadds f6, f8, f31, f30
    fmadds f6, f8, f6, f29
    fmadds f6, f8, f6, f28
    fmadds f6, f8, f6, f27
    addi r15, r16, 0x2000
    andi. r15, r15, 0xc000
    beq @L_80007B9C
    cmpwi r15, 0x4000
    beq @L_80007BA8
    cmplwi r15, 0x8000
    beq @L_80007BB4
    fneg f5, f6
    fmr f4, f7
    b @L_80007BBC
@L_80007B9C:
    fmr f5, f7
    fmr f4, f6
    b @L_80007BBC
@L_80007BA8:
    fmr f5, f6
    fneg f4, f7
    b @L_80007BBC
@L_80007BB4:
    fneg f5, f7
    fneg f4, f6
@L_80007BBC:
    lfs f23, 0x0(r18)
    lfs f24, 0x4(r18)
    lfs f25, 0x8(r18)
    lfs f26, 0xc(r18)
    lfs f27, 0x10(r18)
    lfs f28, 0x14(r18)
    lfs f29, 0x18(r18)
    lfs f30, 0x1c(r18)
    lfs f31, 0x20(r18)
    psq_l f6, 0x18(r28), 1, 5
    lfs f7, 0x4(r22)
    fmuls f6, f6, f29
    fadds f6, f7, f6
    stfs f6, 0xc(r3)
    psq_l f6, 0x1a(r28), 1, 5
    lfs f7, 0x8(r22)
    fmuls f6, f6, f29
    fadds f6, f7, f6
    stfs f6, 0x1c(r3)
    psq_l f6, 0x1c(r28), 1, 5
    lfs f7, 0xc(r22)
    fmuls f6, f6, f29
    fadds f6, f7, f6
    fmuls f7, f0, f5
    stfs f6, 0x2c(r3)
    fmuls f6, f1, f5
    fmuls f8, f1, f4
    fmuls f9, f0, f4
    fmuls f12, f2, f4
    lhz r15, 0xc(r28)
    fmuls f13, f2, f5
    cmpwi r15, 0x0
    bne @L_80007CB8
    stfs f12, 0x0(r3)
    fsubs f14, f30, f3
    stfs f13, 0x10(r3)
@L_80007C4C:
    fmuls f15, f8, f3
    stfs f14, 0x20(r3)
    fsubs f15, f15, f7
    lhz r15, 0xe(r28)
    fmuls f16, f6, f3
    cmpwi r15, 0x0
    bne @L_80007CF8
    stfs f15, 0x4(r3)
    fadds f16, f16, f9
    fmuls f17, f1, f2
    stfs f16, 0x14(r3)
@L_80007C78:
    fmuls f18, f9, f3
    stfs f17, 0x24(r3)
    fadds f18, f18, f6
    lhz r15, 0x10(r28)
    fmuls f19, f7, f3
    cmpwi r15, 0x0
    bne @L_80007D3C
    stfs f18, 0x8(r3)
    fsubs f19, f19, f8
    fmuls f20, f0, f2
    stfs f19, 0x18(r3)
    addi r22, r22, 0x1c
    stfs f20, 0x28(r3)
    cmpw r22, r30
    bne @singlePoseJoint
    b @hierarchy
@L_80007CB8:
    sth r15, 0xc(r1)
    psq_l f10, 0xc(r1), 1, 3
    fmuls f10, f10, f21
    fsubs f14, f30, f3
    fmuls f12, f12, f10
    stfs f12, 0x0(r3)
    fmuls f13, f13, f10
    lhz r15, 0xe(r28)
    fmuls f14, f14, f10
    stfs f13, 0x10(r3)
    cmpwi r15, 0x0
    beq @L_80007C4C
    fmuls f15, f8, f3
    stfs f14, 0x20(r3)
    fsubs f15, f15, f7
    fmuls f16, f6, f3
@L_80007CF8:
    sth r15, 0xc(r1)
    psq_l f10, 0xc(r1), 1, 3
    fmuls f10, f10, f21
    fadds f16, f16, f9
    fmuls f15, f15, f10
    fmuls f17, f1, f2
    stfs f15, 0x4(r3)
    fmuls f16, f16, f10
    lhz r15, 0x10(r28)
    fmuls f17, f17, f10
    stfs f16, 0x14(r3)
    cmpwi r15, 0x0
    beq @L_80007C78
    fmuls f18, f9, f3
    stfs f17, 0x24(r3)
    fadds f18, f18, f6
    fmuls f19, f7, f3
@L_80007D3C:
    sth r15, 0xc(r1)
    psq_l f10, 0xc(r1), 1, 3
    fmuls f10, f10, f21
    fsubs f19, f19, f8
    fmuls f18, f18, f10
    fmuls f20, f0, f2
    stfs f18, 0x8(r3)
    fmuls f19, f19, f10
    stfs f19, 0x18(r3)
    fmuls f20, f20, f10
    addi r22, r22, 0x1c
    stfs f20, 0x28(r3)
    cmpw r22, r30
    bne @singlePoseJoint
@hierarchy:
    lis r21, sJointPairZeroOne@ha
    addi r21, r21, sJointPairZeroOne@l
    psq_l f18, 0x0(r21), 0, 0
    mr r21, r10
    andi. r21, r21, 0xc
    bne @epilogue
    mr r26, r4
    lis r21, lbl_802C3564+0x1900@ha
    addi r21, r21, lbl_802C3564+0x1900@l
    mr r17, r21
    lwz r30, sJointMatrixOutput(r13)
    lwz r25, sJointMatrixBones(r13)
    mr r22, r9
    lbz r19, 0x1(r25)
    slwi r19, r19, 24
    srawi r19, r19, 24
    andi. r23, r19, 0x7f
    and r19, r19, r22
    mr r27, r7
    slwi r20, r27, 6
    add r20, r20, r30
    slwi r20, r23, 6
    add r28, r20, r30
    cmpwi r19, 0x0
    bge @L_80007DF0
    li r23, -0x5
    mcrxr cr0
    addme. r27, r27
    addi r25, r25, 0x1c
    bne @L_80007DF8
    b @epilogue
@L_80007DF0:
    lfs f21, 0x0(r28)
    b @L_80007E4C
@L_80007DF8:
    lbz r19, 0x1(r25)
    slwi r19, r19, 24
    srawi r19, r19, 24
    and. r19, r19, r22
    bge @L_80007E24
    li r23, -0x1
    mcrxr cr0
    addme. r27, r27
    addi r25, r25, 0x1c
    bne @L_80007DF8
    b @epilogue
@L_80007E24:
    slwi r20, r19, 6
    add r28, r20, r30
    add r17, r21, r19
    lbz r20, 0x0(r25)
    cmpw r20, r23
    mr r23, r19
    beq @L_80007E68
    lfs f21, 0x0(r28)
    slwi r26, r20, 6
    add r26, r26, r30
@L_80007E4C:
    psq_l f0, 0x0(r26), 0, 0
    psq_l f1, 0x8(r26), 0, 0
    psq_l f2, 0x10(r26), 0, 0
    psq_l f3, 0x18(r26), 0, 0
    psq_l f4, 0x20(r26), 0, 0
    psq_l f5, 0x28(r26), 0, 0
    b @L_80007E80
@L_80007E68:
    ps_mr f0, f12
    ps_mr f1, f13
    ps_mr f2, f14
    ps_mr f3, f15
    ps_mr f4, f16
    ps_mr f5, f17
@L_80007E80:
    psq_l f6, 0x0(r28), 0, 0
    psq_l f7, 0x8(r28), 0, 0
    psq_l f8, 0x10(r28), 0, 0
    psq_l f9, 0x18(r28), 0, 0
    psq_l f10, 0x20(r28), 0, 0
    psq_l f11, 0x28(r28), 0, 0
    ps_muls0 f12, f6, f0
    ps_muls0 f13, f7, f0
    ps_muls0 f14, f6, f2
    ps_muls0 f15, f7, f2
    ps_muls0 f16, f6, f4
    ps_muls0 f17, f7, f4
    ps_madds1 f12, f8, f0, f12
    ps_madds1 f13, f9, f0, f13
    ps_madds1 f14, f8, f2, f14
    ps_madds1 f15, f9, f2, f15
    ps_madds1 f16, f8, f4, f16
    ps_madds1 f17, f9, f4, f17
    ps_madds0 f12, f10, f1, f12
    ps_madds0 f13, f11, f1, f13
    ps_madds0 f14, f10, f3, f14
    ps_madds0 f15, f11, f3, f15
    ps_madds0 f16, f10, f5, f16
    ps_madds0 f17, f11, f5, f17
    ps_madds1 f13, f18, f1, f13
    ps_madds1 f15, f18, f3, f15
    ps_madds1 f17, f18, f5, f17
    psq_st f12, 0x0(r28), 0, 0
    psq_st f13, 0x8(r28), 0, 0
    psq_st f14, 0x10(r28), 0, 0
    psq_st f15, 0x18(r28), 0, 0
    psq_st f16, 0x20(r28), 0, 0
    psq_st f17, 0x28(r28), 0, 0
    lbz r19, 0x0(r17)
    mcrxr cr0
    addme r27, r27
    addi r25, r25, 0x1c
    cmpwi r27, 0x0
    bne @L_80007DF8
@epilogue:
    lwz r0, 0x100(r1)
    mtlr r0
    lmw r14, 0x24(r1)
    lfd f31, 0xf4(r1)
    lfd f30, 0xec(r1)
    lfd f29, 0xe4(r1)
    lfd f28, 0xdc(r1)
    lfd f27, 0xd4(r1)
    lfd f26, 0xcc(r1)
    lfd f25, 0xc4(r1)
    lfd f24, 0xbc(r1)
    lfd f23, 0xb4(r1)
    lfd f22, 0xac(r1)
    lfd f21, 0xa4(r1)
    lfd f20, 0x9c(r1)
    lfd f19, 0x94(r1)
    lfd f18, 0x8c(r1)
    lfd f17, 0x84(r1)
    lfd f16, 0x7c(r1)
    lfd f15, 0x74(r1)
    lfd f14, 0x6c(r1)
    addi r1, r1, 0xfc
    blr
}
// clang-format on


typedef u64 RenderPackedAddress;

#define RENDER_PACKED_ADDRESS(pointer) ((u32)(pointer))

static inline u16 render_readPackedU16(RenderPackedAddress address) {
    return *(u16*)(u32)address;
}

static inline void render_writePackedU16(RenderPackedAddress address, u16 value) {
    *(u16*)(u32)address = value;
}

/* Refill the two parallel 64-bit bitstream windows from the next
   byte-aligned position once the consumed bit count overruns 64. */
#define RENDER_BITS_REFILL(nb)                                                                                         \
    bitpos -= (nb);                                                                                                    \
    bufA = bitpos >> 3;                                                                                                \
    posA += bufA;                                                                                                      \
    addrB = bufA + curB;                                                                                               \
    curB = addrB;                                                                                                      \
    bitpos &= 7;                                                                                                       \
    render_copyPackedU64Head(&bufA, posA);                                                                             \
    render_copyPackedU64Tail(&bufA, posA + 7);                                                                         \
    render_copyPackedU64Head(&bufB, addrB);                                                                            \
    render_copyPackedU64Tail(&bufB, addrB + 7);                                                                        \
    bufA <<= (bitpos & 0xFFFFFFFF);                                                                                    \
    bufB <<= (bitpos & 0xFFFFFFFF);                                                                                    \
    bitpos += (nb);

#define RENDER_BITS_REFILL_NEXT(nb)                                                                                    \
    bitpos -= (nb);                                                                                                    \
    bufA = bitpos >> 3;                                                                                                \
    posA += bufA;                                                                                                      \
    curB = bufA + curB;                                                                                                \
    bitpos &= 7;                                                                                                       \
    render_copyPackedU64Head(&bufA, posA);                                                                             \
    render_copyPackedU64Tail(&bufA, posA + 7);                                                                         \
    render_copyPackedU64Head(&bufB, curB);                                                                             \
    render_copyPackedU64Tail(&bufB, curB + 7);                                                                         \
    bufA <<= (bitpos & 0xFFFFFFFF);                                                                                    \
    bufB <<= (bitpos & 0xFFFFFFFF);                                                                                    \
    bitpos += (nb);

const f32 gModelRenderSubframeScale[1] = {16384.0f};

void modelRenderInterpolateRootTransform(ObjAnimState* anim, s16* outPosition, s16* outRotation) {
    f32 framePhase;
    u64 tp;
    u64 bitpos;
    int curB;
    u64 posA;
    u64 outPos;
    u64 end;
    u64 bufA;
    u64 bufB;
    s64 tmp;
    s64* q;
    s64 frac;
    u64 vA;
    u32 addrB;
    u64 maskConst;
    int i;

    framePhase = anim->framePhase;
    outPos = RENDER_PACKED_ADDRESS(outRotation);
    curB = anim->frameStreamStride;
    posA = RENDER_PACKED_ADDRESS(anim->frameStreamCursor);
    tp = RENDER_PACKED_ADDRESS(anim->moveFrameData->trackDescriptors);
    q = &tmp;
    maskConst = 0xFFF0;

    addrB = posA + curB;
    curB = addrB;
    end = RENDER_PACKED_ADDRESS(outPosition + 3);
    framePhase -= floorf(framePhase);
    framePhase *= gModelRenderSubframeScale[0];
    frac = (int)framePhase;

    render_copyPackedU64Head(&bufA, posA);
    render_copyPackedU64Tail(&bufA, posA + 7);
    render_copyPackedU64Head(&bufB, addrB);
    render_copyPackedU64Tail(&bufB, addrB + 7);
    bitpos = 0;

    do {
        s64 h = render_readPackedU16(tp);
        u64 nib = h & 0xf;
        u64 sample = 0;
        u32 hw = h;
        h = (u64)hw & maskConst;

        if (nib != 0) {
            bitpos += nib;
            if ((s64)bitpos > 64) {
                RENDER_BITS_REFILL(nib)
            }
            tmp = 64 - nib;
            vA = bufA >> (tmp & 0xFFFFFFFF);
            tmp = bufB >> (tmp & 0xFFFFFFFF);
            tmp -= vA;
            tmp = tmp << 50;
            for (i = 50; i != 0; i--) {
                *q /= 2;
            }
            tmp *= frac;
            for (i = 14; i != 0; i--) {
                *q /= 2;
            }
            sample = h + ((vA + tmp) << 2);
            bufA <<= (nib & 0xFFFFFFFF);
            bufB <<= (nib & 0xFFFFFFFF);
        }
        tp += 2;
        render_writePackedU16(outPos, sample);
        outPos += 2;

        do {
            u64 nib3;

            if ((hw & 0x10) == 0) {
                sample = 0;
                break;
            }
            h = render_readPackedU16(tp);
            if ((h & 0x10) != 0) {
                u64 nib2 = h & 0xf;
                if (nib2 != 0) {
                    bitpos += nib2;
                    if ((s64)bitpos > 64) {
                        RENDER_BITS_REFILL_NEXT(nib2)
                    }
                    bufA <<= (nib2 & 0xFFFFFFFF);
                    bufB <<= (nib2 & 0xFFFFFFFF);
                }
                tp += 2;
                if (((u32)h & 0x20) == 0) {
                    sample = 0;
                    break;
                }
                h = render_readPackedU16(tp);
            }
            sample = 0;
            nib3 = h & 0xf;
            if (nib3 != 0) {
                u64 masked2 = h & 0xFFF0;
                bitpos += nib3;
                if ((s64)bitpos > 64) {
                    RENDER_BITS_REFILL_NEXT(nib3)
                }
                tmp = 64 - nib3;
                vA = bufA >> (tmp & 0xFFFFFFFF);
                tmp = bufB >> (tmp & 0xFFFFFFFF);
                tmp -= vA;
                tmp *= frac;
                for (i = 14; i != 0; i--) {
                    *q /= 2;
                }
                sample = masked2 + (vA + tmp);
                bufA <<= (nib3 & 0xFFFFFFFF);
                bufB <<= (nib3 & 0xFFFFFFFF);
            }
            tp += 2;
        } while (0);
        outPosition[0] = sample;
        outPosition++;
    } while (RENDER_PACKED_ADDRESS(outPosition) != end);
}

static void render_copyPackedU64Tail(u64* dst, u32 packed) {
    /* Preserve the leading bytes of *dst; fill the tail from the aligned
       64-bit word shifted down. */
    u64 src = *(u64*)(packed & ~7);

    switch (packed & 7) {
    case 7:
        *dst = src;
        break;
    case 6:
        *dst = (*dst & 0xff00000000000000ULL) | (src >> 8);
        break;
    case 5:
        *dst = (*dst & 0xffff000000000000ULL) | (src >> 16);
        break;
    case 4:
        *dst = (*dst & 0xffffff0000000000ULL) | (src >> 24);
        break;
    case 3:
        *dst = (*dst & 0xffffffff00000000ULL) | (src >> 32);
        break;
    case 2:
        *dst = (*dst & 0xffffffffff000000ULL) | (src >> 40);
        break;
    case 1:
        *dst = (*dst & 0xffffffffffff0000ULL) | (src >> 48);
        break;
    case 0:
        *dst = (*dst & 0xffffffffffffff00ULL) | (src >> 56);
        break;
    }
}

static void render_copyPackedU64Head(u64* dst, u32 packed) {
    /* Fill the head from the aligned 64-bit word; preserve bytes after the
       unaligned source offset. */
    u64 src = *(u64*)(packed & ~7);

    switch (packed & 7) {
    case 0:
        *dst = src;
        break;
    case 1:
        *dst = (*dst & 0xffULL) | (src << 8);
        break;
    case 2:
        *dst = (*dst & 0xffffULL) | (src << 16);
        break;
    case 3:
        *dst = (*dst & 0xffffffULL) | (src << 24);
        break;
    case 4:
        *dst = (*dst & 0xffffffffULL) | (src << 32);
        break;
    case 5:
        *dst = (*dst & 0xffffffffffULL) | (src << 40);
        break;
    case 6:
        *dst = (*dst & 0xffffffffffffULL) | (src << 48);
        break;
    case 7:
        *dst = (*dst & 0xffffffffffffffULL) | (src << 56);
        break;
    }
}

s16 renderModeSetOrGet(int mode) {
    if (mode != -1) {
        gRenderMode = mode;
        return mode;
    }
    return gRenderMode;
}

int ObjSeq_defaultActionCallback(int unused0, int unused1, int unused2, int unused3, int unused4, int unused5,
                                 int unused6) {
    return -0x1;
}

int getEnvfxActImmediately(void* a, void* b, u16 idx, int d) {
    u8 raw[0x80];
    EnvfxActEntry* e = (EnvfxActEntry*)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, MLDF_FILEID_ENVFXACT_BIN, idx * 0x60, 0x60);
    if (e != NULL) {
        if (e->kind <= 2 || e->kind == 4) {
            (*gNewCloudsInterface)->updateEnvfxAct(a, b, e, d);
        } else if (e->kind == 3) {
            e->fadeDurationA = 0;
            (*gSky2Interface)->updateEnvfxAct(a, b, e, d, idx);
        } else if (e->kind == 5) {
            e->fadeDurationA = 0;
            (*gSkyInterface)->updateEnvfxAct(a, b, e, d);
        } else if (e->kind == 6) {
            (*gCloudActionInterface)->updateEnvfxAct(a, b, e, d, idx);
        }
    }
    return 0;
}

int getEnvfxAct(void* a, void* b, u16 idx, int d) {
    u8 raw[0x80];
    EnvfxActEntry* e = (EnvfxActEntry*)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, MLDF_FILEID_ENVFXACT_BIN, idx * 0x60, 0x60);
    if (e != NULL) {
        if (e->kind <= 2 || e->kind == 4) {
            (*gNewCloudsInterface)->updateEnvfxAct(a, b, e, d);
        } else if (e->kind == 3) {
            (*gSky2Interface)->updateEnvfxAct(a, b, e, d, idx);
        } else if (e->kind == 5) {
            (*gSkyInterface)->updateEnvfxAct(a, b, e, d);
        } else if (e->kind == 6) {
            (*gCloudActionInterface)->updateEnvfxAct(a, b, e, d, idx);
        }
    }
    return 0;
}
