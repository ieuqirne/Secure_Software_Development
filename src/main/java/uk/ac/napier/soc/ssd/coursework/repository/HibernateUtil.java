package uk.ac.napier.soc.ssd.coursework.repository;

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import uk.ac.napier.soc.ssd.coursework.domain.*;

public class HibernateUtil {
    private static SessionFactory sessionFactory = null;

    static {
        try{
            loadSessionFactory();
        }catch(Exception e){
            System.err.println("Exception while initializing hibernate util.. ");
            e.printStackTrace();
        }
    }

    public static void loadSessionFactory(){

        Configuration configuration = new Configuration();
        configuration.configure("j2n-hibernate.cfg.xml");
        configuration.addAnnotatedClass(Course.class);
        configuration.addAnnotatedClass(Program.class);
        configuration.addAnnotatedClass(Enrollment.class);
        configuration.addAnnotatedClass(User.class);
        configuration.addAnnotatedClass(Authority.class);
        configuration.addAnnotatedClass(PersistentToken.class);
        configuration.addAnnotatedClass(PersistentAuditEvent.class);

        ServiceRegistry srvcReg = new StandardServiceRegistryBuilder().applySettings(configuration.getProperties()).build();
        sessionFactory = configuration.buildSessionFactory(srvcReg);
    }

    public static Session getSession() throws HibernateException {

        Session retSession=null;
        try {
            retSession = sessionFactory.openSession();
        }catch(Throwable t){
            System.err.println("Exception while getting session.. ");
            t.printStackTrace();
        }
        if(retSession == null) {
            System.err.println("session is discovered null");
        }

        return retSession;
    }
}
