# -*-coding:utf-8-*-
# print(5//2)


# def recur_get_loc(locarr, ret_list, total_size):
#     membersize = locarr[0]
#     tempsize = total_size + membersize
#     if len(locarr) == 1:
#         if (tempsize % 8) == 0:
#             ret_list.append(total_size)
#             return total_size
#         else:
#             if (tempsize // 8) == (total_size // 8):
#                 ret_list.append(total_size)
#                 return total_size
#             else:
#                 temp=total_size//8+8
#                 ret_list.append(temp)
#                 return temp
#
#     else:
#         presize = locarr[0]
#         pre_realsize = locarr[0]
#         member_size = locarr[0]
#         newlocarr = locarr[1:]
#         if len(newlocarr) >= 1:
#             recur_get_loc(newlocarr, ret_list, member_size)
#
#     pass


# locarr=[1,4,1,4,8,16]
# locarr=[4,5,8,3,12,16,4]
locarr = [4, 4, 4,4,4,4,4,4,4]
# locarr=[4,256,256,4,2,2,16,16,2,2,2,8,16,16,8,8,16,4,4,88,88,4,4,4,16,2,2,4,12,4,4,4]
# locarr=[4,4,4,4]
print(len(locarr))


# member_slice=0
# ture_total_size=0
# pre_realsize=0
# loop=0


def count_location(locarr):
    member_slice = 0
    ture_total_size = 0
    pre_realsize = 0
    loop = 0
    for i in locarr:
        # print(i)
        membersize = i
        if loop == 0:
            pre_realsize = i
            ture_total_size = i
            loop=loop+1
        else:
            print("##############")
            print(str(membersize) + "      membersize")
            if ture_total_size // 8 == (ture_total_size + membersize) // 8:
                print("?????")
                member_slice = member_slice + pre_realsize
            elif ture_total_size // 8 != (ture_total_size + membersize) // 8:
                if (ture_total_size + membersize) % 8 == 0 and (
                        ture_total_size + membersize - 8) // 8 == ture_total_size // 8:
                    print("^^^^^")
                    member_slice = member_slice + pre_realsize

                elif (member_slice + pre_realsize) % 8 == 0:
                    print("******")
                    member_slice = (member_slice + pre_realsize) // 8 * 8
                else:
                    print("%%%%%%%")
                    member_slice = (member_slice + pre_realsize) // 8 * 8 + 8
            print("pre_realsize  " + str(pre_realsize))
            pre_realsize = membersize
            ture_total_size = member_slice + membersize

            print("true_tottal_size...." + str(ture_total_size))

            print(member_slice)
    return member_slice


ret=count_location(locarr)
print(ret)

str="'\\0'"
print(str)
