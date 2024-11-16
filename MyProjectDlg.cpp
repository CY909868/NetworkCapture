
// MyProjectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MyProject.h"
#include "MyProjectDlg.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CMyProjectDlg 对话框




CMyProjectDlg::CMyProjectDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CMyProjectDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	m_hCapThread = NULL;
	m_nCurSel = -1;
}

void CMyProjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_DATA, m_ListData);
	DDX_Control(pDX, IDC_COMBO_DEVICES, m_ComboDevices);
}

BEGIN_MESSAGE_MAP(CMyProjectDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_WM_CTLCOLOR()
	ON_BN_CLICKED(IDC_BTN_START, &CMyProjectDlg::OnBnClickedBtnStart)
	ON_BN_CLICKED(IDC_BTN_STOP, &CMyProjectDlg::OnBnClickedBtnStop)
END_MESSAGE_MAP()


// CMyProjectDlg 消息处理程序

BOOL CMyProjectDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码


	// 初始化ListCtrl
	m_ListData.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP);
	// 列标题
	m_ListData.InsertColumn(0,_T("序号"),LVCFMT_LEFT,70);
	m_ListData.InsertColumn(1,_T("时间"),LVCFMT_LEFT,120);
	m_ListData.InsertColumn(2,_T("协议"),LVCFMT_LEFT,100);
	m_ListData.InsertColumn(3,_T("长度"),LVCFMT_LEFT,80);
	m_ListData.InsertColumn(4,_T("源IP地址"),LVCFMT_LEFT,170);
	m_ListData.InsertColumn(5,_T("目标IP地址"),LVCFMT_LEFT,170);
	m_ListData.InsertColumn(6,_T("消息类型"),LVCFMT_LEFT,150);
	m_ListData.InsertColumn(7,_T("序列号"),LVCFMT_LEFT,150);

	// 获得所有网卡设备
	alldevs = myPcap.GetAllAdapter();
	for(d=alldevs; d; d=d->next)
	{
		m_ComboDevices.InsertString(m_ComboDevices.GetCount(), CString(d->description));
	}
	pcap_freealldevs(d);

	// 初始时没有选中网卡
	m_nCurSel = -1;

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMyProjectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMyProjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMyProjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


HBRUSH CMyProjectDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  Change any attributes of the DC here

	// TODO:  Return a different brush if the default is not desired
	return hbr;
}


void CMyProjectDlg::OnBnClickedBtnStart()
{
	// TODO: Add your control notification handler code here

	if (NULL != m_hCapThread)
	{
		MessageBox(L"已经处于捕获状态，不要重复操作", L"提示");
		return;
	}

	int nIndex = m_ComboDevices.GetCurSel();
	if (CB_ERR == nIndex)
	{	// 没有选中
		MessageBox(L"请先选择网卡设备", L"提示");
		return;
	}
	// 记录选择的网卡编号
	m_nCurSel = nIndex;

	// 定位网卡设备
	int i=0;
	for(i=0, d=alldevs; i<m_nCurSel; d=d->next, i++)
	{
	}

	// 清空
	m_ListData.DeleteAllItems();
	// 临时文件路径
	wchar_t FilePath[256];
	GetModuleFileName(0, FilePath, 255);
	CapFilePath = FilePath;
	CapFilePath = CapFilePath.Left(CapFilePath.ReverseFind('\\'));
	CapFilePath += "\\tmp.CAP";

	// 创建捕获线程
	m_hCapThread = AfxBeginThread(CapThread, (LPVOID)d);

	MessageBox(L"捕获开始", L"提示");
}

void CMyProjectDlg::OnBnClickedBtnStop()
{
	// TODO: Add your control notification handler code here

	if (NULL == m_hCapThread)
	{
		MessageBox(L"没有在捕获", L"提示");
		return;
	}

	// 终止捕获线程
	if(TerminateThread(m_hCapThread->m_hThread, 2) == FALSE)
	{
		MessageBox(L"停止捕获线程失败", L"提示");
		return;
	}

	m_hCapThread = NULL;
	MessageBox(L"捕获停止", L"提示");
}


// 捕获线程
UINT CapThread(LPVOID lpParameter)
{
	pcap_t *adhandle;
	pcap_if_t* devnow = (pcap_if_t*)lpParameter;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int num = 0;
	CString errstring;
	u_int netmask;
	struct bpf_program fcode;

	// 主窗口
	CMyProjectDlg* mDlg = ((CMyProjectDlg*)(AfxGetApp()->GetMainWnd()));

	// 打开网卡
	if ((adhandle = pcap_open(devnow->name,		// 设备名
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,		// 混杂模式
		1000,
		NULL,
		errbuf
		)) == NULL)
	{
		errstring.Format(_T("打开网卡失败"));
		AfxMessageBox(errstring);
		pcap_freealldevs(devnow);
		return -1;
	}
	mDlg->m_adhandle = adhandle;

	if (devnow->addresses != NULL)
	{
		// 获取接口第一个地址的掩码
		netmask = ((struct sockaddr_in *)(devnow->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else
	{
		// 如果这个接口没有地址，那么我们假设这个接口在C类网络中
		netmask = 0xffffff;
	}
	// 编译过滤字符串
	CString strFilter = L"icmp";
	if (pcap_compile(adhandle, &fcode, CStringA(strFilter.GetBuffer()), 1, netmask) < 0)
	{
		errstring = CString("编译过滤字符串失败");
		AfxMessageBox(errstring);
		/* 释放设备列表 */
		pcap_freealldevs(devnow);
		return -1;
	}
	// 设置过滤
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		errstring = CString("设置过滤失败");
		AfxMessageBox(errstring);
		pcap_freealldevs(devnow);
		return -1;
	}

	// 临时存储文件，用于解析数据包
	pcap_dumper_t* dumpfile;
	dumpfile = pcap_dump_open(adhandle, CStringA(CapFilePath.GetBuffer()));
	if(NULL == dumpfile)
	{
		AfxMessageBox(_T("打开临时文件失败"));
		return -1;
	}

	// 开始持续抓包
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
	{
		if(res == 0)
		{	// 超时时间到
			continue;
		}
		++num;
		time_t local_tv_sec;
		struct tm *ltime;
		char timestr[32];

		// 将时间戳转换成可识别的格式
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		char temp[50];
		_itoa(num, temp, 10);
		// 处理以太网首部
		ethernet_header* ethheader = (ethernet_header*)pkt_data;
		// Mac地址
		TCHAR srcMac[18];
		TCHAR desMac[18];
		u_char* tmpSrcMac = ethheader->srcmac;
		u_char* tmpDstMac = ethheader->dstmac;
		swprintf_s(srcMac,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpSrcMac[0],tmpSrcMac[1],tmpSrcMac[2],tmpSrcMac[3],tmpSrcMac[4],tmpSrcMac[5]);
		swprintf_s(desMac,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpDstMac[0],tmpDstMac[1],tmpDstMac[2],tmpDstMac[3],tmpDstMac[4],tmpDstMac[5]);
		char protocaltype[10];
		// 获取以太网包类型
		CMyProjectDlg::GetEthernetType(ethheader, protocaltype);
		TCHAR srcAddr[18];
		TCHAR desAddr[18];
		char srcPort[18] = {0};
		char desPort[18] = {0};
		char type[18] = {0};
		char seq[18] = {0};
		if(CString(protocaltype) == CString("IP"))
		{	// 处理IP协议的类型
			ip_header *ipheader= (ip_header *)(pkt_data+14);
			swprintf_s(srcAddr,16,_T("%d.%d.%d.%d"),ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
			swprintf_s(desAddr,16,_T("%d.%d.%d.%d"),ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
			// 解析是哪种IP包
			CMyProjectDlg::GetIPv4Type(ipheader, protocaltype);
			u_short ipLen = ipheader->ihl*4;
			if (CString(protocaltype) == CString("ICMP"))
			{
				icmp_header *icmpheader= (icmp_header *)(pkt_data+14+ipLen);
				_itoa(icmpheader->type,type,10);
				_itoa(ntohs(int(icmpheader->seq)),seq,10);
			}
			else if (CString(protocaltype) == CString("UDP"))
			{
			}
			else if (CString(protocaltype) == CString("TCP"))
			{
			}
		}
		else if(CString(protocaltype) == CString("ARP"))
		{
			u_char* tmpSrc=ethheader->srcmac;
			u_char* tmpDst=ethheader->dstmac;
			swprintf_s(srcAddr,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpSrc[0],tmpSrc[1],tmpSrc[2],tmpSrc[3],tmpSrc[4],tmpSrc[5]);
			swprintf_s(desAddr,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpDst[0],tmpDst[1],tmpDst[2],tmpDst[3],tmpDst[4],tmpDst[5]);
		}
		else
		{
		}

		// 处理包长度
		char lenstr[10];
		_itoa(header->len,lenstr,10);
		// 插入到列表控件
		int i = mDlg->m_ListData.InsertItem(mDlg->m_ListData.GetItemCount(), CString(temp));
		mDlg->m_ListData.SetTextBkColor(0xFFE070);
		mDlg->m_ListData.SetItemText(i,0,CString(temp));
		mDlg->m_ListData.SetItemText(i,1,CString(timestr));
		mDlg->m_ListData.SetItemText(i,2,CString(protocaltype));
		mDlg->m_ListData.SetItemText(i,3,CString(lenstr));
		mDlg->m_ListData.SetItemText(i,4,CString(srcAddr));
		mDlg->m_ListData.SetItemText(i,5,CString(desAddr));
		mDlg->m_ListData.SetItemText(i,6,CString(type));
		mDlg->m_ListData.SetItemText(i,7,CString(seq));
		CMyPcap::SavePacket(header, pkt_data, dumpfile);
	}

	// 关闭文件
	pcap_dump_close(dumpfile);

	if(res == -1)
	{	// 错误
		CString errstr;
		errstr.Format(_T("读数据包错误: %s\n"), CString(pcap_geterr(adhandle)));
		AfxMessageBox(errstr);
		return -1;
	}

	return 0;
}

// 获得以太网类型
void CMyProjectDlg::GetEthernetType(ethernet_header * e,char *typestr)
{
	u_short etype = ntohs(e->eth_type);
	switch(etype)
	{
	case IP :
		strcpy_s(typestr,10,("IP"));
		break;
	case ARP :
		strcpy_s(typestr,10,("ARP"));
		break;
	default:
		strcpy_s(typestr,10,("UNKNOW"));
		break;
	}
}
// 获得IP类型
void CMyProjectDlg::GetIPv4Type(ip_header* ih, char* pt)
{
	CMyProjectDlg* mDlg = ((CMyProjectDlg*)(AfxGetApp()->GetMainWnd()));
	u_short iptype=ih->proto;
	switch (iptype)
	{
	case TCP:
		strcpy_s(pt,10,"TCP");
		break;
	case UDP:
		strcpy_s(pt,10,"UDP");
		break;
	case ICMP:
		strcpy_s(pt,10,"ICMP");
		break;
	default:
		strcpy_s(pt,10,"OTHER");
		break;
	}
}
// 获得UDP类型
void CMyProjectDlg::GetUDPType(udp_header* udph, char* pt)
{
	strcpy_s(pt,10,"UDP");
}
// 获得TCP类型
void CMyProjectDlg::GetTCPType(tcp_header* tcph, char* pt)
{
	strcpy_s(pt,10,"TCP");
}
