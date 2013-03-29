package net.fatfredyy.certgenerator.cert;

import java.util.Calendar;
import java.util.Date;

public class CertInfoUtil {

	public static Date getNotBeforeDate() {
		Date notBeforeDate = Calendar.getInstance().getTime();
		return notBeforeDate;
	}

	public static Date getNotAfterDate() {
		Calendar notAfter = Calendar.getInstance();
		notAfter.add(Calendar.YEAR, 2);
		Date notAfterDate = notAfter.getTime();
		return notAfterDate;
	}
	
	public static String getSubject() {
		return "CN=Certgenerator test";
	}

}
