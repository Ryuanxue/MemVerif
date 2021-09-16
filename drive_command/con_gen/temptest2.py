from con_gen.lib_code_gen import split_path_pos, split_path_start, judge_isend_start

list1 = ['do_ssl3_writeBB175:8',
         'do_ssl3_writeBB180:7',
         'do_ssl3_writeBB181:1',
         'do_ssl3_writeBB183:5',
         'do_ssl3_writeBB184:6',
         'do_ssl3_writeBB132:4',
         'do_ssl3_writeBB110:3',
         'BBdo_ssl3_write_end',
         'do_ssl3_writeBB139:0',
         'BBdo_ssl3_write_start',
         'do_ssl3_writeBB104:1',
         'do_ssl3_writeBB105:3',
         'do_ssl3_writeBB107:2',
         'do_ssl3_writeBB108:4',
         'do_ssl3_writeBB106:5',
         'do_ssl3_writeBB111:6',
         'BBssl3_write_pending_start',
         'ssl3_write_pendingBB192:1',
         'ssl3_write_pendingBB194:2',
         'ssl3_write_pendingBB196:6',
         'ssl3_write_pendingBB197:8',
         'ssl3_write_pendingBB200:3',
         'ssl3_write_pendingBB201:4',
         'ssl3_write_pendingBB202:5'
         ]
list2 = ['do_ssl3_writeBB175:0',
         'do_ssl3_writeBB180:3',
         'do_ssl3_writeBB181:9',
         'do_ssl3_writeBB183:6',
         'do_ssl3_writeBB184:8',
         'do_ssl3_writeBB132:7',
         'do_ssl3_writeBB110:11',
         'BBdo_ssl3_write_end',
         'do_ssl3_writeBB139:13',
         'BBdo_ssl3_write_start',
         'do_ssl3_writeBB104:2',
         'do_ssl3_writeBB106:3',
         'do_ssl3_writeBB111:4',
         'BBssl3_write_pending_start',
         'ssl3_write_pendingBB192:3',
         'ssl3_write_pendingBB194:4',
         'ssl3_write_pendingBB195:6',
         'ssl3_write_pendingBB196:1',
         'ssl3_write_pendingBB197:2',
         'ssl3_write_pendingBB200:9',
         'ssl3_write_pendingBB201:8',
         'ssl3_write_pendingBB202:7'
         ]

list3=[
    'do_ssl3_writeBB175',
'do_ssl3_writeBB180',
'do_ssl3_writeBB181',
'do_ssl3_writeBB183',
'do_ssl3_writeBB184',
'do_ssl3_writeBB132',
'do_ssl3_writeBB110',
'BBdo_ssl3_write_end',
'do_ssl2_writeBB139',
'BBdo_ssl3_write_start',
'do_ssl3_writeBB104',
'do_ssl3_writeBB105',
'do_ssl3_writeBB107',
'do_ssl3_writeBB108',
'do_ssl3_writeBB106',
'do_ssl3_writeBB111',
'BBssl3_write_pending_start',
'ssl3_write_pendingBB192',
'ssl3_write_pendingBB194',
'ssl3_write_pendingBB196',
'ssl3_write_pendingBB197',
'ssl3_write_pendingBB200',
'ssl3_write_pendingBB201',
'ssl3_write_pendingBB202'
]

Fpath = [list1, list2]


def getfunnmae(elename):
    if elename.endswith("_start"):
        funname = elename[2:-6]
    elif elename.endswith("_end"):
        funname = elename[2:-4]
    else:
        inde = elename.index("BB")
        funname = elename[:inde]
    return funname


def get_classifypath_key(pathlist):
    p1 = pathlist[0]
    prefunname = getfunnmae(p1)
    preele=p1
    k = 1
    key = prefunname + "_" + str(k)
    for i in range(1, len(pathlist)):
        curp = pathlist[i]
        curfunname = getfunnmae(curp)
        print(preele)
        print(curp)
        if preele.endswith("_start") or preele.endswith("_end"):
            k = k + 1
            key = key + "_" + curfunname + "_" + str(k)
            preele=curp
        else:
            preele=curp
    return key


def part_sort(templist):
    sort_templist = []
    for temp_ele in templist:
        # print(temp_ele)
        if temp_ele.endswith("_end") or temp_ele.endswith("_start"):
            sort_templist.append(temp_ele)
            continue
        split_tempele = temp_ele.split(":")
        temp_linenum = int(split_tempele[1])
        if temp_ele == templist[0]:
            sort_templist.append(temp_ele)
            continue

        else:
            if len(sort_templist) == 0:
                sort_templist.append(temp_ele)
            else:
                ret_temp = sort_templist[-1]
                split_rettemp = ret_temp.split(":")
                ret_linenmu = int(split_rettemp[1])
                if temp_linenum > ret_linenmu:
                    sort_templist.append(temp_ele)
                elif temp_linenum == ret_linenmu:
                    sort_templist.append(temp_ele)
                else:
                    for rev in sort_templist[::-1]:
                        split_rev = rev.split(":")
                        rev_linenum = int(split_rev[1])
                        if rev == sort_templist[0] and rev_linenum > temp_linenum:
                            sort_templist.insert(0, temp_ele)
                            break
                        elif rev_linenum < temp_linenum:
                            rev_ind = sort_templist.index(rev)
                            sort_templist.insert(rev_ind + 1, temp_ele)
                            break
                        elif rev_linenum == temp_linenum:
                            rev_ind = sort_templist.index(rev)
                            sort_templist.insert(rev_ind + 1, temp_ele)
                            break
                        elif rev_linenum > temp_linenum:
                            continue
    return sort_templist


def sort_deup1(pa):
    sort_pa = []
    split_list = []
    split_path_pos(pa, split_list)
    split_len = len(split_list)
    for i in range(0, split_len):
        part = split_list[i]
        start = part[0]
        end = part[1]
        per_part = pa[start:end + 1]
        sort_list = part_sort(per_part)
        for ele in sort_list:
            # print(ele)
            sort_pa.append(ele)
    return sort_pa


def merge_two_list_part(list1, list2):
    templist = []

    start_end=list1[-1]
    flag=False
    if start_end.endswith("_end") or start_end.endswith("_start"):
        templist1=list1[0:-1]
        templist2=list2[0:-1]
        flag=True
    else:
        templist1=list1
        templist2=list2
    lenlist1 = len(templist1)
    lenlist2 = len(templist2)
    # print(templist2)


    pt1 = 0
    pt2 = 0
    while (1):
        if pt1 == lenlist1 and pt2 != lenlist2:
            for i in range(pt2, lenlist2):
                tempe = list2[i]
                templist.append(tempe)
            break
        elif pt1 == lenlist1 and pt2 == lenlist2:
            break
        elif pt1 < lenlist1 and pt2 == lenlist2:
            for i in range(pt1, lenlist1):
                tempe = list1[i]
                templist.append(tempe)
            break

        e1 = templist1[pt1]
        e2 = templist2[pt2]
        split_rev = e1.split(":")
        e1line = int(split_rev[1])
        split_rev = e2.split(":")
        e2line = int(split_rev[1])

        if e1line == e2line:
            templist.append(e1)
            pt1 = pt1 + 1
            pt2 = pt2 + 1
            continue
        elif e1line < e2line:
            templist.append(e1)
            pt1 = pt1 + 1
            continue
        else:
            templist.append(e2)
            pt2 = pt2 + 1
            continue
    if flag:
        templist.append(start_end)
    return templist


def merge_two_list(list1, list2):
    split_list1 = []
    split_list2 = []
    # print(list1)
    split_path_pos(list1, split_list1)
    split_path_pos(list2, split_list2)
    part_len = len(split_list2)
    merge_list=[]
    for i in range(0,part_len):
        list1_part = split_list1[i]
        list2_part = split_list2[i]
        list1_start=list1_part[0]
        list1_end=list1_part[1]
        list2_start=list2_part[0]
        list2_end=list2_part[1]
        part_list1=list1[list1_start:list1_end+1]
        part_list2=list2[list2_start:list2_end+1]
        templist=merge_two_list_part(part_list1,part_list2)
        for te in templist:
            merge_list.append(te)
    # for ele in merge_list:
    #     print(ele)
    return merge_list


def class_sort_merge():
    classify_pathlist = {}
    for p in Fpath:
        key = get_classifypath_key(p)
        if key in classify_pathlist.keys():
            classify_pathlist[key].append(p)
        else:
            classify_pathlist[key] = [p]

    for key in classify_pathlist.keys():
        """对每一种类型的路径进行升序和合并"""
        class_path = classify_pathlist[key]
        len_path = len(class_path)
        if len(class_path) > 0:
            list1 = class_path[0]
            sortlist1 = sort_deup1(list1)
            # for ele in sortlist1:
            #     print(ele)
            flen = len(class_path)
            flist = sortlist1
            """sort_pa是升序后的路径"""
            # # print(pa)
            for pth in range(1, flen):
                # print("index.....")
                # print(pth)
                list2 = class_path[pth]
                sortlist2 = sort_deup1(list2)
                templist = merge_two_list(flist, sortlist2)
                flist = templist
    #

def get_all_function(pathlist, split_pathlist):
    start = 0
    end = start
    for p in pathlist:

        if p.endswith("_end"):
            templist = [start, end]
            split_pathlist.append(templist)
            end = end + 1
            start = end
        elif p.endswith("_start"):
            templist = [start, end]
            split_pathlist.append(templist)
            end = end + 1
            start = end
        else:
            end = end + 1
        if p == pathlist[-1]:
            templist = [start, end - 1]
            split_pathlist.append(templist)

if __name__ == '__main__':
    split_pathlist=[]
    split_path_pos(list3,split_pathlist)
    startlist=[]
    split_path_start(list3,startlist)
    ret=judge_isend_start(list3)
    print(ret)
    # print(startlist)
    # print(split_pathlist)
    subpart=[8,9]
    if subpart in split_pathlist:
        print(split_pathlist.index(subpart))
    # for part in split_pathlist:
    #     start=part[0]
    #     end=part[1]
    #     partpath=list3[start:end+1]
    #     print("####")
    #     for i in partpath:
    #         print(i)
    #     if start==0:
    #         pass
    #     elif start+1==end:
    #         preele=list3[start-1]
    #         startele=list3[start]
    #         prefunname=getfunnmae(preele)
    #         startfunname=getfunnmae(startele)
    #         if prefunname==startfunname:
    #             print("recur....")
    #         else:
    #             print("judge startele 是否有loop")
    #         # print(list3[start-1])
    #         # print(list3[start])
    #         # print(list3[end])
    #
    # print(split_pathlist)


