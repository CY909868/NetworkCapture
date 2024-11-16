
// MyProjectDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"


#include "MyPcap.h"
#include "afxwin.h"


// 捕获线程
static UINT CapThread(LPVOID lpParameter);


static CString FilterString;	// 捕获过滤字符串
static CString CapFilePath;		// 临时抓包文件路径


// CMyProjectDlg 对话框
class CMyProjectDlg : public CDialog
{
// 构造
public:
	CMyProjectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_MYPROJECT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	DECLARE_MESSAGE_MAP()

public:
	afx_msg void OnBnClickedBtnStart();
	afx_msg void OnBnClickedBtnStop();
	CListCtrl m_ListData;
	CComboBox m_ComboDevices;
	pcap_t*	m_adhandle;	// 打开的网卡


public:
	// 获得以太网类型
	static void GetEthernetType(ethernet_header * e,char *typestr);
	// 获得IP类型
	static void GetIPv4Type(ip_header* ih, char* pt);
	// 获得UDP类型
	static void GetUDPType(udp_header* udph, char* pt);
	// 获得TCP类型
	static void GetTCPType(tcp_header* tcph, char* pt);


private:
	CMyPcap		myPcap;		// winpcap
	pcap_if_t	*alldevs;
	pcap_if_t	*d;
	int			m_nCurSel;		// 当前选中的网卡编号
	CWinThread* m_hCapThread;	// 捕获线程
	char m_pSrcIP[32];
	char m_pDstIP[32];
};
