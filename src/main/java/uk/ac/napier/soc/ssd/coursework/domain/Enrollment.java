package uk.ac.napier.soc.ssd.coursework.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import javax.persistence.*;

import org.springframework.data.elasticsearch.annotations.Document;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.Objects;

import uk.ac.napier.soc.ssd.coursework.domain.enumeration.EntryLevel;

/**
 * A Enrollment.
 */
@Entity
@Table(name = "enrollment")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
@Document(indexName = "enrollment")
public class Enrollment implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "entry_level")
    private EntryLevel entryLevel;

    @Lob
    @Column(name = "comments")
    private String comments;

    @ManyToOne
    @JsonIgnoreProperties("")
    private User user;

    @ManyToMany
    @Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
    @JoinTable(name = "enrollment_course",
               joinColumns = @JoinColumn(name = "enrollments_id", referencedColumnName = "id"),
               inverseJoinColumns = @JoinColumn(name = "courses_id", referencedColumnName = "id"))
    private Set<Course> courses = new HashSet<>();

    // jhipster-needle-entity-add-field - JHipster will add fields here, do not remove
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public EntryLevel getEntryLevel() {
        return entryLevel;
    }

    public Enrollment entryLevel(EntryLevel entryLevel) {
        this.entryLevel = entryLevel;
        return this;
    }

    public void setEntryLevel(EntryLevel entryLevel) {
        this.entryLevel = entryLevel;
    }

    public String getComments() {
        return comments;
    }

    public Enrollment comments(String comments) {
        this.comments = comments;
        return this;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    public User getUser() {
        return user;
    }

    public Enrollment user(User user) {
        this.user = user;
        return this;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Set<Course> getCourses() {
        return courses;
    }

    public Enrollment courses(Set<Course> courses) {
        this.courses = courses;
        return this;
    }

    public Enrollment addCourse(Course course) {
        this.courses.add(course);
        course.getEnrollments().add(this);
        return this;
    }

    public Enrollment removeCourse(Course course) {
        this.courses.remove(course);
        course.getEnrollments().remove(this);
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
        Enrollment enrollment = (Enrollment) o;
        if (enrollment.getId() == null || getId() == null) {
            return false;
        }
        return Objects.equals(getId(), enrollment.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    @Override
    public String toString() {
        return "Enrollment{" +
            "id=" + getId() +
            ", entryLevel='" + getEntryLevel() + "'" +
            ", comments='" + getComments() + "'" +
            "}";
    }
}
