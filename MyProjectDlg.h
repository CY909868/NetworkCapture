
// MyProjectDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"


#include "MyPcap.h"
#include "afxwin.h"


// �����߳�
static UINT CapThread(LPVOID lpParameter);


static CString FilterString;	// ��������ַ���
static CString CapFilePath;		// ��ʱץ���ļ�·��


// CMyProjectDlg �Ի���
class CMyProjectDlg : public CDialog
{
// ����
public:
	CMyProjectDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_MYPROJECT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
	pcap_t*	m_adhandle;	// �򿪵�����


public:
	// �����̫������
	static void GetEthernetType(ethernet_header * e,char *typestr);
	// ���IP����
	static void GetIPv4Type(ip_header* ih, char* pt);
	// ���UDP����
	static void GetUDPType(udp_header* udph, char* pt);
	// ���TCP����
	static void GetTCPType(tcp_header* tcph, char* pt);


private:
	CMyPcap		myPcap;		// winpcap
	pcap_if_t	*alldevs;
	pcap_if_t	*d;
	int			m_nCurSel;		// ��ǰѡ�е��������
	CWinThread* m_hCapThread;	// �����߳�
	char m_pSrcIP[32];
	char m_pDstIP[32];
};
