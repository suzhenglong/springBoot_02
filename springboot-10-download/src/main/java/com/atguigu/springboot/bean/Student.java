package com.atguigu.springboot.bean;

import java.util.Date;

/**
 * @Description:
 * @author: zhenglongsu@163.com
 * @date: 2019.10.27 17:32
 */
public class Student {

    private String id;
    private String name;
    private String sex;
    private String grade;
    private String score;
    private Date birthdate;

    public Student(String id, String name, String sex, String grade, String score, Date birthdate) {
        this.id = id;
        this.name = name;
        this.sex = sex;
        this.grade = grade;
        this.score = score;
        this.birthdate = birthdate;
    }

    public Date getBirthdate() {
        return birthdate;
    }

    public void setBirthdate(Date birthdate) {
        this.birthdate = birthdate;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSex() {
        return sex;
    }

    public void setSex(String sex) {
        this.sex = sex;
    }

    public String getGrade() {
        return grade;
    }

    public void setGrade(String grade) {
        this.grade = grade;
    }

    public String getScore() {
        return score;
    }

    public void setScore(String score) {
        this.score = score;
    }
}
