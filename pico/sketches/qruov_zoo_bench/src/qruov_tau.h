#pragma once
#if (QRUOV_q == 127) && (QRUOV_L == 3) && (QRUOV_v == 156) && (QRUOV_m == 54)
#  define QRUOV_tau1    4267 // n1 = L*V*(V+1)/2 :    4134
#  define QRUOV_tau2    2916 // n2 = L*V*M       :    2808
#  define QRUOV_tau3     192 // n3 = L*V = v     :     156
#  define QRUOV_tau4      82 // n4 = L*M = m     :      54
#elif (QRUOV_q == 31) && (QRUOV_L == 3) && (QRUOV_v == 165) && (QRUOV_m == 60)
#  define QRUOV_tau1    4959 // n1 = L*V*(V+1)/2 :    4620
#  define QRUOV_tau2    3571 // n2 = L*V*M       :    3300
#  define QRUOV_tau3     226 // n3 = L*V = v     :     165
#  define QRUOV_tau4     104 // n4 = L*M = m     :      60
#elif (QRUOV_q == 31) && (QRUOV_L == 10) && (QRUOV_v == 600) && (QRUOV_m == 70)
#  define QRUOV_tau1   19242 // n1 = L*V*(V+1)/2 :   18300
#  define QRUOV_tau2    4518 // n2 = L*V*M       :    4200
#  define QRUOV_tau3     704 // n3 = L*V = v     :     600
#  define QRUOV_tau4     116 // n4 = L*M = m     :      70
#elif (QRUOV_q == 7) && (QRUOV_L == 10) && (QRUOV_v == 740) && (QRUOV_m == 100)
#  define QRUOV_tau1   32629 // n1 = L*V*(V+1)/2 :   27750
#  define QRUOV_tau2    8947 // n2 = L*V*M       :    7400
#  define QRUOV_tau3    1024 // n3 = L*V = v     :     740
#  define QRUOV_tau4     201 // n4 = L*M = m     :     100
#elif (QRUOV_q == 127) && (QRUOV_L == 3) && (QRUOV_v == 228) && (QRUOV_m == 78)
#  define QRUOV_tau1    9020 // n1 = L*V*(V+1)/2 :    8778
#  define QRUOV_tau2    6123 // n2 = L*V*M       :    5928
#  define QRUOV_tau3     283 // n3 = L*V = v     :     228
#  define QRUOV_tau4     120 // n4 = L*M = m     :      78
#elif (QRUOV_q == 31) && (QRUOV_L == 3) && (QRUOV_v == 246) && (QRUOV_m == 87)
#  define QRUOV_tau1   10878 // n1 = L*V*(V+1)/2 :   10209
#  define QRUOV_tau2    7655 // n2 = L*V*M       :    7134
#  define QRUOV_tau3     338 // n3 = L*V = v     :     246
#  define QRUOV_tau4     154 // n4 = L*M = m     :      87
#elif (QRUOV_q == 31) && (QRUOV_L == 10) && (QRUOV_v == 890) && (QRUOV_m == 100)
#  define QRUOV_tau1   41974 // n1 = L*V*(V+1)/2 :   40050
#  define QRUOV_tau2    9507 // n2 = L*V*M       :    8900
#  define QRUOV_tau3    1046 // n3 = L*V = v     :     890
#  define QRUOV_tau4     169 // n4 = L*M = m     :     100
#elif (QRUOV_q == 7) && (QRUOV_L == 10) && (QRUOV_v == 1100) && (QRUOV_m == 140)
#  define QRUOV_tau1   71432 // n1 = L*V*(V+1)/2 :   61050
#  define QRUOV_tau2   18461 // n2 = L*V*M       :   15400
#  define QRUOV_tau3    1526 // n3 = L*V = v     :    1100
#  define QRUOV_tau4     289 // n4 = L*M = m     :     140
#elif (QRUOV_q == 127) && (QRUOV_L == 3) && (QRUOV_v == 306) && (QRUOV_m == 105)
#  define QRUOV_tau1   16144 // n1 = L*V*(V+1)/2 :   15759
#  define QRUOV_tau2   11018 // n2 = L*V*M       :   10710
#  define QRUOV_tau3     380 // n3 = L*V = v     :     306
#  define QRUOV_tau4     162 // n4 = L*M = m     :     105
#elif (QRUOV_q == 31) && (QRUOV_L == 3) && (QRUOV_v == 324) && (QRUOV_m == 114)
#  define QRUOV_tau1   18738 // n1 = L*V*(V+1)/2 :   17658
#  define QRUOV_tau2   13145 // n2 = L*V*M       :   12312
#  define QRUOV_tau3     447 // n3 = L*V = v     :     324
#  define QRUOV_tau4     203 // n4 = L*M = m     :     114
#elif (QRUOV_q == 31) && (QRUOV_L == 10) && (QRUOV_v == 1120) && (QRUOV_m == 120)
#  define QRUOV_tau1   66236 // n1 = L*V*(V+1)/2 :   63280
#  define QRUOV_tau2   14326 // n2 = L*V*M       :   13440
#  define QRUOV_tau3    1324 // n3 = L*V = v     :    1120
#  define QRUOV_tau4     210 // n4 = L*M = m     :     120
#elif (QRUOV_q == 7) && (QRUOV_L == 10) && (QRUOV_v == 1490) && (QRUOV_m == 190)
#  define QRUOV_tau1  130305 // n1 = L*V*(V+1)/2 :  111750
#  define QRUOV_tau2   33694 // n2 = L*V*M       :   28310
#  define QRUOV_tau3    2065 // n3 = L*V = v     :    1490
#  define QRUOV_tau4     391 // n4 = L*M = m     :     190
#else
#  error "unknown (q,L,v,m)"
#endif
