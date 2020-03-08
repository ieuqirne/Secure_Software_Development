package uk.ac.napier.soc.ssd.coursework.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import javax.persistence.*;
import javax.validation.constraints.*;

import org.springframework.data.elasticsearch.annotations.Document;
import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.Objects;

/**
 * A Program.
 */
@Entity
@Table(name = "program")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
@Document(indexName = "program")
public class Program implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Size(min = 2)
    @Column(name = "name", nullable = false)
    private String name;

    @NotNull
    @Column(name = "start_date", nullable = false)
    private Instant startDate;

    @Column(name = "max_students")
    private Long maxStudents;

    @ManyToMany(mappedBy = "programs")
    @JsonIgnore
    @Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
    private Set<Course> courses = new HashSet<>();

    // jhipster-needle-entity-add-field - JHipster will add fields here, do not remove
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public Program name(String name) {
        this.name = name;
        return this;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Instant getStartDate() {
        return startDate;
    }

    public Program startDate(Instant startDate) {
        this.startDate = startDate;
        return this;
    }

    public void setStartDate(Instant startDate) {
        this.startDate = startDate;
    }

    public Long getMaxStudents() {
        return maxStudents;
    }

    public Program maxStudents(Long maxStudents) {
        this.maxStudents = maxStudents;
        return this;
    }

    public void setMaxStudents(Long maxStudents) {
        this.maxStudents = maxStudents;
    }

    public Set<Course> getCourses() {
        return courses;
    }

    public Program courses(Set<Course> courses) {
        this.courses = courses;
        return this;
    }

    public Program addCourse(Course course) {
        this.courses.add(course);
        course.getPrograms().add(this);
        return this;
    }

    public Program removeCourse(Course course) {
        this.courses.remove(course);
        course.getPrograms().remove(this);
        return this;
    }

    public void setCourses(Set<Course> courses) {
        this.courses = courses;
    }
    // jhipster-needle-entity-add-getters-setters - JHipster will add getters and setters here, do not remove

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Program program = (Program) o;
        if (program.getId() == null || getId() == null) {
            return false;
        }
        return Objects.equals(getId(), program.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    @Override
    public String toString() {
        return "Program{" +
            "id=" + getId() +
            ", name='" + getName() + "'" +
            ", startDate='" + getStartDate() + "'" +
            ", maxStudents=" + getMaxStudents() +
            "}";
    }
}
