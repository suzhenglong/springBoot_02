package com.atguigu.springboot.controller;

import com.atguigu.springboot.bean.Address;
import com.atguigu.springboot.bean.Student;
import com.atguigu.springboot.mapper.AddressMapper;
import jxl.Workbook;
import jxl.format.Alignment;
import jxl.format.Border;
import jxl.format.BorderLineStyle;
import jxl.format.Colour;
import jxl.format.VerticalAlignment;
import jxl.format.*;
import jxl.write.*;
import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.xssf.usermodel.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import sun.misc.BASE64Decoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @Description:
 * @author: zhenglongsu@163.com
 * @date: 2019.10.27 14:24
 */
@RestController
public class DownController {

    @RequestMapping(value = "/downLoadPublicKey", method = RequestMethod.POST)
    @ResponseBody
    public void downLoadPublicKey(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String publicKey = "MIIDIzCCAgugAwIBAgIEOuy3rjANBgkqhkiG9w0BAQQFADBNMQowCAYDVQQGEwE1MQowCAYDVQQI\n" +
                "EwE2MQowCAYDVQQHEwE3MQowCAYDVQQKEwE0MQowCAYDVQQLEwEzMQ8wDQYDVQQDEwZSb290Q0Ew\n" +
                "HhcNMTkwOTEwMDg1MjQwWhcNMjIwOTA5MDg1MjQwWjBaMQ0wCwYDVQQGEwR0ZXN0MQ0wCwYDVQQI\n" +
                "EwR0ZXN0MQ0wCwYDVQQHEwR0ZXN0MQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQ0wCwYD\n" +
                "VQQDEwR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwmeBJfichEWPqO3iA4FY\n" +
                "qyeMVhgrwR7R5pFru2NZmTcjPfRnnV2tdQYp65Jyd/4qXpLxGlr6QmkRlhJUqtMUk1h3TjH/mH8q\n" +
                "39A00KPJE6hxiNJ0c9JSMRr45Gtutrj5fxLuihwbcB5tLjQxYb76t3z9blYpt/P4rWHTSvWmJR1E\n" +
                "YBu6QJwP8w0xOki4VeK4fP+cS5TEN95K3e5qSVCzkNjysUp5KheU7U2AkBmcLJNK0Zpbe9Vr7ZVG\n" +
                "GKZ3Qnm2Y/MRYjr+dUsY8bLDoQNfNEVxAwjkhItTMC/nbEpN4wnaB90nJSVsx9FadWid371QI6F5\n" +
                "6wvg9IbZSp/Rg1Q8bwIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQAOo851U+7dDfpYyn0g14lotawM\n" +
                "MOHAKs1TSxbOpxwDU84XZptV0pRrRgIVgz6mC3a4QIrWF/E7yEhKhsGNwYWY7HNcfmk+vN3YdJjf\n" +
                "HYuL1DN6WbrlcRtwg/L/umJYYxQ7gvx7sNMzwbkqT8ZvjykFeCMa7RyepUXAmcN/WCtSmhyxGcLI\n" +
                "KgS4BQv7lb65FkKwzahdTGoHQsPU/nFN+PC9YfFb4+67rfJYwj0yGIcTZCQERtIx+cJYnr1xV5uo\n" +
                "17erDJR5PT1EbBLPekSlFB0ZgLPXIuqSW3x4a5MkErkKsxVYpsk+x8erf/03vZRHm2q4+PYpNzVo\n" +
                "3KyL0xDkN127";
        byte[] bytes = new BASE64Decoder().decodeBuffer(publicKey);//将字符串转换为byte数组
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);//将数组转换为文件流
        byte[] buffer = new byte[256];
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        String filename = "public_key_" + dateFormat.format(new Date()) + ".crt";//文件名称
        response.reset();//重置response
        response.setHeader("Content-Disposition", "attachment; filename=" + filename);
        OutputStream out = null;
        try {
            int len = 0;
            out = response.getOutputStream();
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }
    }

    @Autowired
    AddressMapper addressMapper;


    @RequestMapping(value = "/downLoadExcel", method = RequestMethod.POST)
    @ResponseBody
    public void downLoadExcel(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // 文件名
        String filename = "地址列表.xls";

        try {
            // 写到服务器上
            String path = request.getSession().getServletContext().getRealPath("") + "/" + filename;

            // 写到服务器上（这种测试过，在本地可以，放到linux服务器就不行）
            //String path =  this.getClass().getClassLoader().getResource("").getPath()+"/"+filename;

            File name = new File(path);
            // 创建写工作簿对象
            WritableWorkbook workbook = Workbook.createWorkbook(name);
            // 工作表
            WritableSheet sheet = workbook.createSheet("地址列表", 0);
            // 设置字体;
            WritableFont font = new WritableFont(WritableFont.ARIAL, 14, WritableFont.BOLD, false,
                    UnderlineStyle.NO_UNDERLINE, Colour.BLACK);

            WritableCellFormat cellFormat = new WritableCellFormat(font);
            // 设置背景颜色;
            cellFormat.setBackground(Colour.WHITE);
            // 设置边框;
            cellFormat.setBorder(Border.ALL, BorderLineStyle.DASH_DOT);
            // 设置文字居中对齐方式;
            cellFormat.setAlignment(Alignment.CENTRE);
            // 设置垂直居中;
            cellFormat.setVerticalAlignment(VerticalAlignment.CENTRE);
            // 分别给1,5,6列设置不同的宽度;
            sheet.setColumnView(0, 15);
            sheet.setColumnView(4, 60);
            sheet.setColumnView(5, 35);
            // 给sheet电子版中所有的列设置默认的列的宽度;
            sheet.getSettings().setDefaultColumnWidth(20);
            // 给sheet电子版中所有的行设置默认的高度，高度的单位是1/20个像素点,但设置这个貌似就不能自动换行了
            // sheet.getSettings().setDefaultRowHeight(30 * 20);
            // 设置自动换行;
            cellFormat.setWrap(true);

            // 单元格
            Label label0 = new Label(0, 0, "ID", cellFormat);
            Label label1 = new Label(1, 0, "省", cellFormat);
            Label label2 = new Label(2, 0, "市", cellFormat);
            Label label3 = new Label(3, 0, "区", cellFormat);
            Label label4 = new Label(4, 0, "详细地址", cellFormat);
            Label label5 = new Label(5, 0, "创建时间", cellFormat);

            sheet.addCell(label0);
            sheet.addCell(label1);
            sheet.addCell(label2);
            sheet.addCell(label3);
            sheet.addCell(label4);
            sheet.addCell(label5);

            // 给第二行设置背景、字体颜色、对齐方式等等;
            WritableFont font2 = new WritableFont(WritableFont.ARIAL, 14, WritableFont.NO_BOLD, false,
                    UnderlineStyle.NO_UNDERLINE, Colour.BLACK);
            WritableCellFormat cellFormat2 = new WritableCellFormat(font2);
            // 设置文字居中对齐方式;
            cellFormat2.setAlignment(Alignment.CENTRE);
            // 设置垂直居中;
            cellFormat2.setVerticalAlignment(VerticalAlignment.CENTRE);
            cellFormat2.setBackground(Colour.WHITE);
            cellFormat2.setBorder(Border.ALL, BorderLineStyle.THIN);
            cellFormat2.setWrap(true);

            // 记录行数
            int n = 1;

            // 查找所有地址
            List<Address> addressList = addressMapper.queryList();
            if (addressList != null && addressList.size() > 0) {

                // 遍历
                for (Address a : addressList) {

                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    String createTime = sdf.format(a.getCreateTime());

                    Label lt0 = new Label(0, n, a.getId() + "", cellFormat2);
                    Label lt1 = new Label(1, n, a.getProvince(), cellFormat2);
                    Label lt2 = new Label(2, n, a.getCity(), cellFormat2);
                    Label lt3 = new Label(3, n, a.getArea(), cellFormat2);
                    Label lt4 = new Label(4, n, a.getAddress(), cellFormat2);
                    Label lt5 = new Label(5, n, createTime, cellFormat2);

                    sheet.addCell(lt0);
                    sheet.addCell(lt1);
                    sheet.addCell(lt2);
                    sheet.addCell(lt3);
                    sheet.addCell(lt4);
                    sheet.addCell(lt5);

                    n++;
                }
            }

            //开始执行写入操作
            workbook.write();
            //关闭流
            workbook.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        // 第六步，下载excel

        OutputStream out = null;
        try {
            response.addHeader("content-disposition", "attachment;filename="
                    + java.net.URLEncoder.encode(filename, "utf-8"));

            // 2.下载
            out = response.getOutputStream();
            String path3 = request.getSession().getServletContext().getRealPath("") + "/" + filename;

            // inputStream：读文件，前提是这个文件必须存在，要不就会报错
            InputStream is = new FileInputStream(path3);

            byte[] b = new byte[4096];
            int size = is.read(b);
            while (size > 0) {
                out.write(b, 0, size);
                size = is.read(b);
            }
            out.close();
            is.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @return void
     * @author suzhenglong
     * @Description XSSF:xlsx
     * HSSF:xls
     * HSSF是POI工程对Excel 97(-2007)文件操作的纯Java实现
     * XSSF是POI工程对Excel 2007 OOXML (.xlsx)文件操作的纯Java实现
     * @date 2019.10.27 16:45
     */
    @RequestMapping(value = "/downLoadExcelHSSF", method = RequestMethod.POST)
    @ResponseBody
    public void downLoadExcelHSSF(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 创建工作薄
        HSSFWorkbook wb = new HSSFWorkbook();
        // 在工作薄上建一张工作表
        HSSFSheet sheet = wb.createSheet();
        HSSFRow row = sheet.createRow((short) 0);
        sheet.createFreezePane(0, 1);
        cteateCell(wb, row, (short) 0, "学号");
        cteateCell(wb, row, (short) 1, "姓名");
        cteateCell(wb, row, (short) 2, "性别");
        cteateCell(wb, row, (short) 3, "班级");
        cteateCell(wb, row, (short) 4, "分数");
        cteateCell(wb, row, (short) 5, "出生日期");
        cteateCell(wb, row, (short) 6, "出生日期1");
        int i = 0;

        List<Student> list = new ArrayList();

        for (int k = 9; k > -1; k--) {
            list.add(new Student(k + "", "孙是" + k, "男", "高三" + k + "班", "9" + k, new Date()));
        }

        for (Student student : list) {
            HSSFRow rowi = sheet.createRow((short) (++i));
            for (int j = 0; j < 4; j++) {
                cteateCell(wb, rowi, (short) 0, student.getId());
                cteateCell(wb, rowi, (short) 1, student.getName());
                cteateCell(wb, rowi, (short) 2, student.getSex());
                cteateCell(wb, rowi, (short) 3, student.getGrade());
                cteateCell(wb, rowi, (short) 4, student.getScore());
                cteateCell(wb, rowi, (short) 5, student.getBirthdate().toString());
                cteateCell(wb, rowi, (short) 6, getTimeStamp("yyyy-MM-dd hh:MM:ss"));
            }
        }

        String fname = "xls_" + getTimeStamp("yyyyMMddHHmmss") + "_";// Excel文件名
        OutputStream os = response.getOutputStream();// 取得输出流
        response.reset();// 清空输出流
        response.setHeader("Content-disposition", "attachment; filename="
                + fname + ".xls"); // 设定输出文件头,该方法有两个参数，分别表示应答头的名字和值。
        response.setContentType("application/msexcel");

        wb.write(os);
        os.flush();
        os.close();
        System.out.println("文件生成");
    }

    @RequestMapping(value = "/downLoadExcelXSSF", method = RequestMethod.POST)
    @ResponseBody
    public void downLoadExcelXSSF(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 创建工作薄
        XSSFWorkbook wb = new XSSFWorkbook();
        // sheet1
        XSSFSheet sheet = wb.createSheet();
        //设置列宽
        sheet.setColumnWidth(2, 4000);
        sheet.setColumnWidth(3, 6000);

        XSSFRow row = sheet.createRow((short) 0);
        sheet.createFreezePane(0, 1);
        sheet.createFreezePane(0, 1);
        cteateCellXssf(wb, row, (short) 0, "学号");
        cteateCellXssf(wb, row, (short) 1, "姓名");
        cteateCellXssf(wb, row, (short) 2, "性别");
        cteateCellXssf(wb, row, (short) 3, "班级");
        cteateCellXssf(wb, row, (short) 4, "分数");
        cteateCellXssf(wb, row, (short) 5, "出生日期");
        cteateCellXssf(wb, row, (short) 6, "出生日期1");
        int i = 0;

        List<Student> list = new ArrayList();

        for (int k = 0; k < 10; k++) {
            list.add(new Student(k + "", "孙是" + k, "男", "高三" + k + "班", "9" + k, new Date()));
        }

        for (Student student : list) {
            XSSFRow rowi = sheet.createRow((short) (++i));
            for (int j = 0; j < 4; j++) {
                cteateCellXssf(wb, rowi, (short) 0, student.getId());
                cteateCellXssf(wb, rowi, (short) 1, student.getName());
                cteateCellXssf(wb, rowi, (short) 2, student.getSex());
                cteateCellXssf(wb, rowi, (short) 3, student.getGrade());
                cteateCellXssf(wb, rowi, (short) 4, student.getScore());
                cteateCellXssf(wb, rowi, (short) 5, student.getBirthdate().toString());
                cteateCellXssf(wb, rowi, (short) 6, getTimeStamp("yyyy-MM-dd hh:MM:ss"));
            }
        }

        String fname = "xlsx_" + getTimeStamp("yyyyMMddHHmmss") + "_";// Excel文件名
        OutputStream os = response.getOutputStream();// 取得输出流
        response.reset();// 清空输出流
        response.setHeader("Content-disposition", "attachment; filename="
                + fname + ".xlsx"); // 设定输出文件头,该方法有两个参数，分别表示应答头的名字和值。
        response.setContentType("application/msexcel");

        wb.write(os);
        os.flush();
        os.close();
        System.out.println("文件生成");


    }


    @SuppressWarnings("deprecation")
    private void cteateCellXssf(XSSFWorkbook wb, XSSFRow row, short col, String val) {
        //设置行高
        row.setHeight((short) 480);
        XSSFCell cell = row.createCell(col);
        cell.setCellValue(val);
        XSSFCellStyle cellstyle = wb.createCellStyle();
        //HSSFFont Font = wb.createFont();
        //Font.setFontHeightInPoints((short) 10);
        //cellstyle.setFont(Font);
        cellstyle.setAlignment(XSSFCellStyle.ALIGN_CENTER);
        cellstyle.setBorderBottom(XSSFCellStyle.BORDER_THIN); //下边框
        cellstyle.setBorderLeft(XSSFCellStyle.BORDER_THIN);//左边框
        cellstyle.setBorderTop(XSSFCellStyle.BORDER_THIN);//上边框
        cellstyle.setBorderRight(XSSFCellStyle.BORDER_THIN);//右边框
        cell.setCellStyle(cellstyle);
    }

    /**
     * 该方法用来产生一个时间字符串（即：时间戳）
     *
     * @return
     */
    public static String getTimeStamp(String format) {
        SimpleDateFormat dateFormat = new SimpleDateFormat(format);
        Date date = new Date();
        return dateFormat.format(date);
    }

    @SuppressWarnings("deprecation")
    private void cteateCell(HSSFWorkbook wb, HSSFRow row, short col, String val) {
        HSSFCell cell = row.createCell(col);
        cell.setCellValue(val);
    }


}
