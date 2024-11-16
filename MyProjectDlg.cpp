
// MyProjectDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "MyProject.h"
#include "MyProjectDlg.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CMyProjectDlg �Ի���




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


// CMyProjectDlg ��Ϣ�������

BOOL CMyProjectDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������


	// ��ʼ��ListCtrl
	m_ListData.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP);
	// �б���
	m_ListData.InsertColumn(0,_T("���"),LVCFMT_LEFT,70);
	m_ListData.InsertColumn(1,_T("ʱ��"),LVCFMT_LEFT,120);
	m_ListData.InsertColumn(2,_T("Э��"),LVCFMT_LEFT,100);
	m_ListData.InsertColumn(3,_T("����"),LVCFMT_LEFT,80);
	m_ListData.InsertColumn(4,_T("ԴIP��ַ"),LVCFMT_LEFT,170);
	m_ListData.InsertColumn(5,_T("Ŀ��IP��ַ"),LVCFMT_LEFT,170);
	m_ListData.InsertColumn(6,_T("��Ϣ����"),LVCFMT_LEFT,150);
	m_ListData.InsertColumn(7,_T("���к�"),LVCFMT_LEFT,150);

	// ������������豸
	alldevs = myPcap.GetAllAdapter();
	for(d=alldevs; d; d=d->next)
	{
		m_ComboDevices.InsertString(m_ComboDevices.GetCount(), CString(d->description));
	}
	pcap_freealldevs(d);

	// ��ʼʱû��ѡ������
	m_nCurSel = -1;

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CMyProjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
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
		MessageBox(L"�Ѿ����ڲ���״̬����Ҫ�ظ�����", L"��ʾ");
		return;
	}

	int nIndex = m_ComboDevices.GetCurSel();
	if (CB_ERR == nIndex)
	{	// û��ѡ��
		MessageBox(L"����ѡ�������豸", L"��ʾ");
		return;
	}
	// ��¼ѡ����������
	m_nCurSel = nIndex;

	// ��λ�����豸
	int i=0;
	for(i=0, d=alldevs; i<m_nCurSel; d=d->next, i++)
	{
	}

	// ���
	m_ListData.DeleteAllItems();
	// ��ʱ�ļ�·��
	wchar_t FilePath[256];
	GetModuleFileName(0, FilePath, 255);
	CapFilePath = FilePath;
	CapFilePath = CapFilePath.Left(CapFilePath.ReverseFind('\\'));
	CapFilePath += "\\tmp.CAP";

	// ���������߳�
	m_hCapThread = AfxBeginThread(CapThread, (LPVOID)d);

	MessageBox(L"����ʼ", L"��ʾ");
}

void CMyProjectDlg::OnBnClickedBtnStop()
{
	// TODO: Add your control notification handler code here

	if (NULL == m_hCapThread)
	{
		MessageBox(L"û���ڲ���", L"��ʾ");
		return;
	}

	// ��ֹ�����߳�
	if(TerminateThread(m_hCapThread->m_hThread, 2) == FALSE)
	{
		MessageBox(L"ֹͣ�����߳�ʧ��", L"��ʾ");
		return;
	}

	m_hCapThread = NULL;
	MessageBox(L"����ֹͣ", L"��ʾ");
}


// �����߳�
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

	// ������
	CMyProjectDlg* mDlg = ((CMyProjectDlg*)(AfxGetApp()->GetMainWnd()));

	// ������
	if ((adhandle = pcap_open(devnow->name,		// �豸��
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,		// ����ģʽ
		1000,
		NULL,
		errbuf
		)) == NULL)
	{
		errstring.Format(_T("������ʧ��"));
		AfxMessageBox(errstring);
		pcap_freealldevs(devnow);
		return -1;
	}
	mDlg->m_adhandle = adhandle;

	if (devnow->addresses != NULL)
	{
		// ��ȡ�ӿڵ�һ����ַ������
		netmask = ((struct sockaddr_in *)(devnow->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else
	{
		// �������ӿ�û�е�ַ����ô���Ǽ�������ӿ���C��������
		netmask = 0xffffff;
	}
	// ��������ַ���
	CString strFilter = L"icmp";
	if (pcap_compile(adhandle, &fcode, CStringA(strFilter.GetBuffer()), 1, netmask) < 0)
	{
		errstring = CString("��������ַ���ʧ��");
		AfxMessageBox(errstring);
		/* �ͷ��豸�б� */
		pcap_freealldevs(devnow);
		return -1;
	}
	// ���ù���
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		errstring = CString("���ù���ʧ��");
		AfxMessageBox(errstring);
		pcap_freealldevs(devnow);
		return -1;
	}

	// ��ʱ�洢�ļ������ڽ������ݰ�
	pcap_dumper_t* dumpfile;
	dumpfile = pcap_dump_open(adhandle, CStringA(CapFilePath.GetBuffer()));
	if(NULL == dumpfile)
	{
		AfxMessageBox(_T("����ʱ�ļ�ʧ��"));
		return -1;
	}

	// ��ʼ����ץ��
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
	{
		if(res == 0)
		{	// ��ʱʱ�䵽
			continue;
		}
		++num;
		time_t local_tv_sec;
		struct tm *ltime;
		char timestr[32];

		// ��ʱ���ת���ɿ�ʶ��ĸ�ʽ
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		char temp[50];
		_itoa(num, temp, 10);
		// ������̫���ײ�
		ethernet_header* ethheader = (ethernet_header*)pkt_data;
		// Mac��ַ
		TCHAR srcMac[18];
		TCHAR desMac[18];
		u_char* tmpSrcMac = ethheader->srcmac;
		u_char* tmpDstMac = ethheader->dstmac;
		swprintf_s(srcMac,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpSrcMac[0],tmpSrcMac[1],tmpSrcMac[2],tmpSrcMac[3],tmpSrcMac[4],tmpSrcMac[5]);
		swprintf_s(desMac,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpDstMac[0],tmpDstMac[1],tmpDstMac[2],tmpDstMac[3],tmpDstMac[4],tmpDstMac[5]);
		char protocaltype[10];
		// ��ȡ��̫��������
		CMyProjectDlg::GetEthernetType(ethheader, protocaltype);
		TCHAR srcAddr[18];
		TCHAR desAddr[18];
		char srcPort[18] = {0};
		char desPort[18] = {0};
		char type[18] = {0};
		char seq[18] = {0};
		if(CString(protocaltype) == CString("IP"))
		{	// ����IPЭ�������
			ip_header *ipheader= (ip_header *)(pkt_data+14);
			swprintf_s(srcAddr,16,_T("%d.%d.%d.%d"),ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
			swprintf_s(desAddr,16,_T("%d.%d.%d.%d"),ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
			// ����������IP��
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

		// ���������
		char lenstr[10];
		_itoa(header->len,lenstr,10);
		// ���뵽�б�ؼ�
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

	// �ر��ļ�
	pcap_dump_close(dumpfile);

	if(res == -1)
	{	// ����
		CString errstr;
		errstr.Format(_T("�����ݰ�����: %s\n"), CString(pcap_geterr(adhandle)));
		AfxMessageBox(errstr);
		return -1;
	}

	return 0;
}

// �����̫������
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
// ���IP����
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
// ���UDP����
void CMyProjectDlg::GetUDPType(udp_header* udph, char* pt)
{
	strcpy_s(pt,10,"UDP");
}
// ���TCP����
void CMyProjectDlg::GetTCPType(tcp_header* tcph, char* pt)
{
	strcpy_s(pt,10,"TCP");
}
